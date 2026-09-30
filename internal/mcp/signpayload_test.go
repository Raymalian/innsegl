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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/signing"
)

// RM-241 (#386) — ADR-0059 decision 4: the gates and phases of the commit-sign
// path, as one in-process call. Test IDs CMT-007..012 (doc 07).
//
// Every gate case below asserts TWO things: the call is refused, and NOTHING
// was appended to the ledger before that refusal (ADR-0059 decision 4: "no
// gate may append anything; a refusal before Phase A leaves the chain
// unchanged"). An assertion that only checked the error would pass against an
// implementation that appended commit_intent and then decided, too late, to
// refuse.

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const (
	spRunID     = "run-cmt241"
	spToolUseID = "toolu_01cmt241abcdefghijklmnop"
	spTaskRef   = "RM-241"
	spTaskID    = "rm-241"
	spRepo      = "github.com/innsegl/innsegl"
	spAuthor    = "operator@innsegl.invalid"
)

func spSPIFFEID(runID string) string {
	return "spiffe://innsegl.dev/agent/demo/" + spTaskID + "/" + runID
}

// spClaim is the claimFor fixture's answer for spRunID: the identical
// construction sign_commit's own phases() makes, so what gate 2 compares
// against is what a real ClaimFor implementation would produce.
func spClaim(runID string) signing.Claim {
	return signing.Claim{Identity: spSPIFFEID(runID), Run: runID, Task: spTaskRef}
}

// spResolver is commitpath.Resolver: a map from tool call id to whatever
// commitpath.Resolve should read back. Gate 1 is commitpath.Resolve's own —
// tested exhaustively in internal/commitpath — so this fixture only needs to
// hand back what a real traffic relay would.
type spResolver struct {
	calls map[string]commitpath.RelayedCall
}

func (r spResolver) LookupPending(toolUseID string) (commitpath.RelayedCall, bool) {
	c, ok := r.calls[toolUseID]
	return c, ok
}

// spPendingGitCommit is a relayed, still-running `git commit` Bash call for
// runID, observed just now — gate 1's happy path.
func spPendingGitCommit(runID string) commitpath.RelayedCall {
	return commitpath.RelayedCall{
		RunID:      runID,
		Tool:       "Bash",
		Input:      json.RawMessage(`{"command":"git commit -m x"}`),
		ObservedAt: time.Now(),
	}
}

// spPayload renders a well-formed, signable payload whose trailers are
// exactly claim.Trailers() — gate 2's happy path — with the given author and
// committer emails, so gate 3's cases can vary just those two fields.
func spPayload(t *testing.T, claim signing.Claim, authorEmail, committerEmail string) []byte {
	t.Helper()
	return spPayloadWithTree(t, claim, strings.Repeat("a", 40), authorEmail, committerEmail)
}

// spPayloadWithTree is spPayload with the tree line parameterised, for cases
// that need a REAL tree a local git repository actually holds (Phase A's own
// patch-id computation shells out to git — see spLocalRepo).
func spPayloadWithTree(t *testing.T, claim signing.Claim, tree, authorEmail, committerEmail string) []byte {
	t.Helper()
	trailers, err := claim.Trailers()
	if err != nil {
		t.Fatalf("claim.Trailers: %v", err)
	}
	var b strings.Builder
	b.WriteString("the commit message\n\n")
	for _, tr := range trailers {
		b.WriteString(tr.String())
		b.WriteString("\n")
	}
	message := b.String()
	return []byte(fmt.Sprintf(
		"tree %s\n"+
			"author Author Name <%s> 1700000000 +0000\n"+
			"committer Committer Name <%s> 1700000000 +0000\n"+
			"\n%s",
		tree, authorEmail, committerEmail, message))
}

// spPayloadWithParent is spPayloadWithTree with one `parent` header line —
// commitPathPatchID's two-tree form (against the named parent) rather than
// its root-commit form (against the empty tree).
func spPayloadWithParent(t *testing.T, claim signing.Claim, tree, parent, authorEmail, committerEmail string) []byte {
	t.Helper()
	trailers, err := claim.Trailers()
	if err != nil {
		t.Fatalf("claim.Trailers: %v", err)
	}
	var b strings.Builder
	b.WriteString("the commit message\n\n")
	for _, tr := range trailers {
		b.WriteString(tr.String())
		b.WriteString("\n")
	}
	return []byte(fmt.Sprintf(
		"tree %s\n"+
			"parent %s\n"+
			"author Author Name <%s> 1700000000 +0000\n"+
			"committer Committer Name <%s> 1700000000 +0000\n"+
			"\n%s",
		tree, parent, authorEmail, committerEmail, b.String()))
}

// spLocalRepo makes a real, local git repository — no Docker, no Sigstore —
// with one staged file, and returns its directory and the tree
// `git write-tree` reports for it. It exists so Phase A's own patch-id
// computation (commitPathPatchID, which shells out to git) can succeed in a
// gate-level test, without needing the real SPIRE/Fulcio/Rekor stack
// TestCMT010AndCMT012AgainstRealSigstoreAndARealChain requires.
func spLocalRepo(t *testing.T) (dir, tree string) {
	t.Helper()
	dir = t.TempDir()
	scGit(t, dir, "init", "-q", "-b", "main")
	scStage(t, dir, "work.txt", "commit-sign path unit fixture\n")
	tree = scGit(t, dir, "write-tree")
	return dir, tree
}

// spLocalRepoWithParent is spLocalRepo with a real first commit already
// made (a plain, unattributed local commit — gpgsign disabled — the test's
// own git process, not this session's tool call), so a second staged
// change has a real parent to name. It exists to exercise
// commitPathPatchID's two-tree form (a payload with a `parent` header),
// which spLocalRepo's root-commit shape never reaches.
func spLocalRepoWithParent(t *testing.T) (dir, tree, parent string) {
	t.Helper()
	dir = t.TempDir()
	scGit(t, dir, "init", "-q", "-b", "main")
	scStage(t, dir, "base.txt", "commit-sign path unit fixture: base\n")
	scGit(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	parent = scGit(t, dir, "rev-parse", "HEAD")
	scStage(t, dir, "work.txt", "commit-sign path unit fixture: second change\n")
	tree = scGit(t, dir, "write-tree")
	return dir, tree, parent
}

// spWiring is a sign_commit wiring (newSCWiring, sign_commit_test.go) plus
// the two dependencies ADR-0059 decision 4 adds beyond it, both installed
// through the package's own configuration entry points — never by writing to
// package state directly, so this test exercises the identical seam
// production wiring uses.
type spWiring struct {
	sc                   *scWiring
	resolver             spResolver
	restoreSC, restoreSP func()
}

func newSPWiring(t *testing.T, resolver spResolver, claimFor func(context.Context, string) (signing.Claim, error)) *spWiring {
	t.Helper()
	sc := newSCWiring()
	// newSCWiring's run fixture is scRunID ("run-rm033"); the commit-sign
	// path has no run_id argument of its own to disagree with, so every gate
	// case here is written in terms of spRunID instead, and the fixture is
	// made to match it rather than the other way around.
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{
		Resolver: resolver,
		ClaimFor: claimFor,
	})
	if err != nil {
		restoreSC()
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	w := &spWiring{sc: sc, resolver: resolver, restoreSC: restoreSC, restoreSP: restoreSP}
	t.Cleanup(func() {
		w.restoreSP()
		w.restoreSC()
	})
	return w
}

func spClaimForOK(t *testing.T) func(context.Context, string) (signing.Claim, error) {
	t.Helper()
	return func(_ context.Context, runID string) (signing.Claim, error) {
		if runID != spRunID {
			return signing.Claim{}, fmt.Errorf("no claim for run %q", runID)
		}
		return spClaim(runID), nil
	}
}

// requireNoLedgerWrite is ADR-0059 decision 4's "no gate may append
// anything": the wiring's ledger fake (scLedger, sign_commit_test.go) records
// every Append call regardless of outcome, so an empty record set is a direct
// assertion that Append was never even attempted.
func requireNoLedgerWrite(t *testing.T, w *spWiring) {
	t.Helper()
	if got := w.sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) were appended; none should have been", len(got))
	}
	if got := w.sc.ledger.ofType(event.EventTypeCommitRecorded); len(got) != 0 {
		t.Errorf("%d commit_recorded event(s) were appended; none should have been", len(got))
	}
}

// ---------------------------------------------------------------------------
// CMT-007 (I) — a forged or missing id at signing is refused before any
// signing attempt, and no commit_intent is appended.
// ---------------------------------------------------------------------------

func TestCMT007AForgedOrMissingToolUseIDIsRefusedBeforeAnySigningAttempt(t *testing.T) {
	claim := spClaim(spRunID)
	payload := spPayload(t, claim, spAuthor, spAuthor)

	cases := []struct {
		name      string
		toolUseID string
		resolver  spResolver
	}{
		{
			name:      "empty tool_use_id",
			toolUseID: "",
			resolver:  spResolver{calls: map[string]commitpath.RelayedCall{}},
		},
		{
			name:      "malformed tool_use_id",
			toolUseID: "not-a-tool-use-id",
			resolver:  spResolver{calls: map[string]commitpath.RelayedCall{}},
		},
		{
			name:      "well-formed id the relay never saw (forged)",
			toolUseID: spToolUseID,
			resolver:  spResolver{calls: map[string]commitpath.RelayedCall{}},
		},
		{
			name:      "the relayed call is not a Bash tool call",
			toolUseID: spToolUseID,
			resolver: spResolver{calls: map[string]commitpath.RelayedCall{
				spToolUseID: {RunID: spRunID, Tool: "Read", ObservedAt: time.Now()},
			}},
		},
		{
			name:      "the relayed call's command is not a git commit",
			toolUseID: spToolUseID,
			resolver: spResolver{calls: map[string]commitpath.RelayedCall{
				spToolUseID: {
					RunID: spRunID, Tool: "Bash",
					Input:      json.RawMessage(`{"command":"git status"}`),
					ObservedAt: time.Now(),
				},
			}},
		},
		{
			name:      "the relayed call's input arrived truncated",
			toolUseID: spToolUseID,
			resolver: spResolver{calls: map[string]commitpath.RelayedCall{
				spToolUseID: {
					RunID: spRunID, Tool: "Bash",
					Input:      json.RawMessage(`{"command":"git commit -m x"}`),
					Truncated:  true,
					ObservedAt: time.Now(),
				},
			}},
		},
		{
			name:      "the relayed call is older than commitpath.Window",
			toolUseID: spToolUseID,
			resolver: spResolver{calls: map[string]commitpath.RelayedCall{
				spToolUseID: {
					RunID: spRunID, Tool: "Bash",
					Input:      json.RawMessage(`{"command":"git commit -m x"}`),
					ObservedAt: time.Now().Add(-2 * commitpath.Window),
				},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newSPWiring(t, tc.resolver, spClaimForOK(t))
			_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
				ToolUseID: tc.toolUseID,
				Args:      []string{"--status-fd=2", "-bsau", "x"},
				Payload:   payload,
			})
			if err == nil {
				t.Fatal("SignPayloadForGateway succeeded; want a refusal")
			}
			requireNoLedgerWrite(t, w)
		})
	}
}

// ---------------------------------------------------------------------------
// CMT-008 (I) — payload trailers that are not the ones rendered for this
// tool call's run are refused before Phase A.
// ---------------------------------------------------------------------------

func TestCMT008MismatchedTrailersAreRefusedBeforePhaseA(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}

	cases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "a different run's trailers entirely",
			payload: spPayload(t, spClaim("run-somebody-else"), spAuthor, spAuthor),
		},
		{
			name: "the identity trailer altered by one character",
			payload: func() []byte {
				p := spPayload(t, spClaim(spRunID), spAuthor, spAuthor)
				return []byte(strings.Replace(string(p),
					"Agent-Identity: "+spSPIFFEID(spRunID),
					"Agent-Identity: "+spSPIFFEID(spRunID)+"x", 1))
			}(),
		},
		{
			name: "no trailers at all",
			payload: []byte(fmt.Sprintf(
				"tree %s\nauthor A <%s> 1700000000 +0000\ncommitter A <%s> 1700000000 +0000\n\nplain message\n",
				strings.Repeat("a", 40), spAuthor, spAuthor)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newSPWiring(t, resolver, spClaimForOK(t))
			_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
				ToolUseID: spToolUseID,
				Args:      []string{"--status-fd=2", "-bsau", "x"},
				Payload:   tc.payload,
			})
			if err == nil {
				t.Fatal("SignPayloadForGateway succeeded; want a refusal")
			}
			requireNoLedgerWrite(t, w)
		})
	}
}

// ---------------------------------------------------------------------------
// CMT-009 (I) — an author or committer the policy does not admit is refused
// (I6), before Phase A.
// ---------------------------------------------------------------------------

func TestCMT009AnUnadmittedAuthorOrCommitterIsRefusedBeforePhaseA(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	claim := spClaim(spRunID)

	cases := []struct {
		name           string
		authorEmail    string
		committerEmail string
	}{
		{"author not admitted", "nobody@corp.example", spAuthor},
		{"committer not admitted", spAuthor, "nobody@corp.example"},
		{"neither admitted", "nobody@corp.example", "somebody-else@corp.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newSPWiring(t, resolver, spClaimForOK(t))
			// scSigners.Admits (sign_commit_test.go) refuses any email once
			// admitErr is set — the same fake sign_commit's own I6 cases use.
			w.sc.signers.admitErr = signing.ErrAuthorNotAdmitted
			_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
				ToolUseID: spToolUseID,
				Args:      []string{"--status-fd=2", "-bsau", "x"},
				Payload:   spPayload(t, claim, tc.authorEmail, tc.committerEmail),
			})
			if err == nil {
				t.Fatal("SignPayloadForGateway succeeded; want a refusal")
			}
			if !errors.Is(err, signing.ErrAuthorNotAdmitted) {
				t.Errorf("error = %v, want it to wrap %v", err, signing.ErrAuthorNotAdmitted)
			}
			requireNoLedgerWrite(t, w)
		})
	}
}

// ---------------------------------------------------------------------------
// Configuration refusals — the same discipline sign_commit's own
// newSignCommitService holds itself to: a missing dependency blocks every
// call rather than leaving a gate silently unchecked.
// ---------------------------------------------------------------------------

func TestConfigureSignPayloadRefusesAMissingResolver(t *testing.T) {
	_, err := ConfigureSignPayload(SignPayloadConfig{ClaimFor: spClaimForOK(t)})
	if err == nil {
		t.Fatal("ConfigureSignPayload with no resolver succeeded; want a refusal")
	}
}

func TestConfigureSignPayloadRefusesAMissingClaimFor(t *testing.T) {
	_, err := ConfigureSignPayload(SignPayloadConfig{
		Resolver: spResolver{calls: map[string]commitpath.RelayedCall{}},
	})
	if err == nil {
		t.Fatal("ConfigureSignPayload with no claim function succeeded; want a refusal")
	}
}

// TestAValidPayloadPassesGates1Through3AndReachesPhaseA is the positive
// counterpart CMT-007..009 need: a refusal-only suite passes trivially
// against an implementation that refuses EVERYTHING, so this proves the gates
// actually ADMIT a well-formed request rather than merely reject malformed
// ones. It stops short of a real signature (that is CMT-010, against real
// Sigstore) by using newSCWiring's fake workspace directory, which is not a
// real git repository — so Phase A's own patch-id computation is where this
// is expected to fail, and the assertion is that it fails THERE and not at
// any of gates 1-3.
func TestAValidPayloadPassesGates1Through3AndReachesPhaseA(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	claim := spClaim(spRunID)
	w := newSPWiring(t, resolver, spClaimForOK(t))

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2", "-bsau", "x"},
		Payload:   spPayload(t, claim, spAuthor, spAuthor),
	})
	if err == nil {
		t.Fatal("SignPayloadForGateway succeeded against a fake, non-git workspace; want a failure past the gates")
	}
	if errors.Is(err, signing.ErrAuthorNotAdmitted) {
		t.Errorf("failed at the I6 gate (%v); the fixture's author and committer are admitted", err)
	}
	if !strings.Contains(err.Error(), w.sc.space.dir) && !strings.Contains(err.Error(), "git") {
		t.Errorf("error = %v; want a failure naming the workspace (%s) or git, evidence "+
			"this got past gates 1-3 into Phase A's own patch-id computation", err, w.sc.space.dir)
	}
	requireNoLedgerWrite(t, w)
}

func TestSignPayloadForGatewayRefusesWhenNotConfigured(t *testing.T) {
	// Neither ConfigureSignPayload nor ConfigureSignCommit has been called in
	// this test's own scope: package state may carry whatever an earlier test
	// in this binary left restored to nil, which is what every other test's
	// t.Cleanup guarantees.
	signCommitMu.RLock()
	activeAtStart := signCommitActive
	signCommitMu.RUnlock()
	signPayloadMu.RLock()
	cfgAtStart := signPayloadCfg
	signPayloadMu.RUnlock()
	if activeAtStart != nil || cfgAtStart != nil {
		t.Skip("another test left package state installed; order-dependent, skipping")
	}
	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: []byte("irrelevant"),
	})
	if err == nil {
		t.Fatal("SignPayloadForGateway succeeded with nothing configured; want a refusal")
	}
}

func TestSignPayloadForGatewayRefusesWhenSignCommitIsNotConfigured(t *testing.T) {
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{
		Resolver: spResolver{calls: map[string]commitpath.RelayedCall{
			spToolUseID: spPendingGitCommit(spRunID),
		}},
		ClaimFor: spClaimForOK(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	signCommitMu.RLock()
	activeAtStart := signCommitActive
	signCommitMu.RUnlock()
	if activeAtStart != nil {
		t.Skip("another test left sign_commit configured; order-dependent, skipping")
	}

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "sign_commit is not configured") {
		t.Fatalf("error = %v, want a refusal naming sign_commit as unconfigured", err)
	}
}

func TestConfigureSignPayloadAcceptsACustomNow(t *testing.T) {
	var called bool
	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	restore, err := ConfigureSignPayload(SignPayloadConfig{
		Resolver: spResolver{calls: map[string]commitpath.RelayedCall{}},
		ClaimFor: spClaimForOK(t),
		Now:      func() time.Time { called = true; return fixed },
	})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restore()

	signCommitMu.RLock()
	needSC := signCommitActive == nil
	signCommitMu.RUnlock()
	if needSC {
		sc := newSCWiring()
		restoreSC, cerr := ConfigureSignCommit(sc.cfg)
		if cerr != nil {
			t.Fatalf("ConfigureSignCommit: %v", cerr)
		}
		defer restoreSC()
	}

	// A tool call id the resolver has never heard of still reaches
	// commitpath.Resolve, which calls Now() to check the window — enough to
	// prove the custom clock is actually wired in, without needing the rest
	// of the gates to succeed.
	if _, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: []byte("irrelevant"),
	}); err == nil {
		t.Error("an unknown tool call id was not refused")
	}
	if !called {
		t.Error("the configured Now was never called")
	}
}

// ---------------------------------------------------------------------------
// Gate 2 — the payload itself, and the claim it is checked against.
// ---------------------------------------------------------------------------

func TestGate2RefusesAPayloadThatDoesNotEvenParse(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	w := newSPWiring(t, resolver, spClaimForOK(t))
	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   []byte("this is not a git commit object at all"),
	})
	if !errors.Is(err, signing.ErrPayload) {
		t.Fatalf("error = %v, want %v", err, signing.ErrPayload)
	}
	requireNoLedgerWrite(t, w)
}

func TestGate2RefusesWhenClaimForItselfErrors(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	claimFor := func(context.Context, string) (signing.Claim, error) {
		return signing.Claim{}, errors.New("claimFor: no such run known to the gateway")
	}
	w := newSPWiring(t, resolver, claimFor)
	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "no claim for run") {
		t.Fatalf("error = %v, want a refusal naming the missing claim", err)
	}
	requireNoLedgerWrite(t, w)
}

func TestGate2RefusesWhenTheClaimIsInternallyInconsistent(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	// Run does not match the {run_id} segment of Identity, so
	// claim.Trailers() itself refuses — before this function ever compares
	// anything against the payload.
	bad := signing.Claim{Identity: spSPIFFEID(spRunID), Run: "not-" + spRunID, Task: spTaskRef}
	claimFor := func(context.Context, string) (signing.Claim, error) { return bad, nil }
	w := newSPWiring(t, resolver, claimFor)
	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	if !errors.Is(err, signing.ErrClaim) {
		t.Fatalf("error = %v, want %v", err, signing.ErrClaim)
	}
	requireNoLedgerWrite(t, w)
}

// ---------------------------------------------------------------------------
// Gate 3 — the committer specifically, with the author admitted. CMT-009
// sets one admitErr for both emails at once (scSigners.Admits ignores its
// argument); this reaches the SECOND Admits call, which CMT-009 cannot.
// ---------------------------------------------------------------------------

// spPerEmailPolicy is SignCommitSigners with a per-email I6 decision —
// scSigners (sign_commit_test.go) cannot express this, because its
// Admits ignores which email it was asked about.
type spPerEmailPolicy struct{ refuse string }

func (p spPerEmailPolicy) Admits(email string) error {
	if email == p.refuse {
		return signing.ErrAuthorNotAdmitted
	}
	return nil
}

func (spPerEmailPolicy) Open(signing.CredentialSource) (SignCommitSigner, error) {
	return nil, errors.New("spPerEmailPolicy: Open is not implemented; this fixture is for gate 3 only")
}

func TestGate3RefusesAnUnadmittedCommitterWithTheAuthorAdmitted(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	const committerEmail = "committer-only@corp.example"
	sc.cfg.Signers = spPerEmailPolicy{refuse: committerEmail}
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, committerEmail),
	})
	if !errors.Is(err, signing.ErrAuthorNotAdmitted) {
		t.Fatalf("error = %v, want %v", err, signing.ErrAuthorNotAdmitted)
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) were appended; none should have been", len(got))
	}
}

// ---------------------------------------------------------------------------
// Gate 4 — the run, its working tree, and its credential.
// ---------------------------------------------------------------------------

func TestGate4RefusesARunTheRunDirectoryDoesNotKnow(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc := newSCWiring()
	sc.runs.found = false // the run directory has never heard of spRunID
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	classified := Classify(err)
	if classified.Class != ClassRunNotFound {
		t.Fatalf("error class = %s, want %s (err=%v)", classified.Class, ClassRunNotFound, err)
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) were appended; none should have been", len(got))
	}
}

func TestGate4RefusesARunWithNoRegisteredRepository(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: "", // no repository on the record
	}
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "carries no repository") {
		t.Fatalf("error = %v, want a refusal naming the missing repository", err)
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) were appended; none should have been", len(got))
	}
}

func TestGate4RefusesWhenTheWorkspaceCannotResolveAWorkingTree(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	sc.space.err = errors.New("no such working tree")
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "no working tree") {
		t.Fatalf("error = %v, want a refusal naming the working tree", err)
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) were appended; none should have been", len(got))
	}
}

func TestGate4RefusesWhenTheCredentialCannotBeIssued(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	sc.creds.err = errors.New("get_credential: SPIRE is unreachable")
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	})
	if err == nil {
		t.Fatal("want a refusal when the credential cannot be issued")
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) were appended; none should have been", len(got))
	}
}

// ---------------------------------------------------------------------------
// Phase A and the seam into Phase B — a REAL local git repository (no
// Docker, no Sigstore) so commitPathPatchID's own git plumbing succeeds,
// with fakes for everything past it. This is what lets a gate-level test
// reach Phase A's append and the signer-type check right after it, neither
// of which a fake, non-git workspace (the rest of this file's gate cases)
// can ever get past.
// ---------------------------------------------------------------------------

// spWiringWithRepo is newSPWiring's construction, minus its fake workspace
// directory: the workspace resolves to a real local git repository instead,
// so Phase A's patch-id computation succeeds.
func spWiringWithRepo(t *testing.T, resolver spResolver) (w *scWiring, repo, tree string) {
	t.Helper()
	repo, tree = spLocalRepo(t)
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	sc.space.dir = repo
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		restoreSC()
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	t.Cleanup(func() { restoreSP(); restoreSC() })
	return sc, repo, tree
}

// TestPhaseAAppendsTheIntentThenRefusesAtPhaseBWithoutAGitsignSigner proves
// Phase A itself: a real tree, a real patch id, a commit_intent that carries
// both — and then the signer-type check (Phase B needs the shipped
// gitsign wrapper; newSCWiring's fake is not it) refuses before anything
// resembling a signature exists. No commit_recorded follows.
func TestPhaseAAppendsTheIntentThenRefusesAtPhaseBWithoutAGitsignSigner(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc, _, tree := spWiringWithRepo(t, resolver)
	claim := spClaim(spRunID)

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2"},
		Payload:   spPayloadWithTree(t, claim, tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "does not support the commit-sign path") {
		t.Fatalf("error = %v, want a refusal naming the unsupported signer factory", err)
	}

	intents := sc.ledger.ofType(event.EventTypeCommitIntent)
	if len(intents) != 1 {
		t.Fatalf("%d commit_intent events, want exactly 1", len(intents))
	}
	if got := scMember[string](t, intents[0], event.FieldTreeHash); got != tree {
		t.Errorf("commit_intent tree_hash = %q, want %q", got, tree)
	}
	if got := scMember[string](t, intents[0], event.FieldRepo); got != spRepo {
		t.Errorf("commit_intent repo = %q, want %q", got, spRepo)
	}
	if recorded := sc.ledger.ofType(event.EventTypeCommitRecorded); len(recorded) != 0 {
		t.Errorf("%d commit_recorded event(s); Phase B never ran, so there should be none", len(recorded))
	}
}

// TestPhaseAComputesThePatchIDAgainstANamedParent is
// TestPhaseAAppendsTheIntentThenRefusesAtPhaseBWithoutAGitsignSigner's
// sibling for a payload that names a real parent: commitPathPatchID's
// two-tree form (diff-tree against the parent) rather than its root-commit
// form (diff-tree against the empty tree) — the branch a root-commit
// payload can never reach.
func TestPhaseAComputesThePatchIDAgainstANamedParent(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	repo, tree, parent := spLocalRepoWithParent(t)
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	sc.space.dir = repo
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	claim := spClaim(spRunID)
	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2"},
		Payload:   spPayloadWithParent(t, claim, tree, parent, spAuthor, spAuthor),
	})
	// Phase B still refuses (newSCWiring's signer factory is a fake), but
	// Phase A must have gotten there first: commit_intent on the chain,
	// carrying THIS tree, computed against the named parent rather than the
	// empty tree.
	if err == nil || !strings.Contains(err.Error(), "does not support the commit-sign path") {
		t.Fatalf("error = %v, want a refusal naming the unsupported signer factory", err)
	}
	intents := sc.ledger.ofType(event.EventTypeCommitIntent)
	if len(intents) != 1 {
		t.Fatalf("%d commit_intent events, want exactly 1", len(intents))
	}
	if got := scMember[string](t, intents[0], event.FieldTreeHash); got != tree {
		t.Errorf("commit_intent tree_hash = %q, want %q", got, tree)
	}
}

func TestPhaseARefusesWhenTheLedgerCannotAppendTheIntent(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc, _, tree := spWiringWithRepo(t, resolver)
	sc.ledger.failOn[event.EventTypeCommitIntent] = errors.New("the chain is unreachable")
	claim := spClaim(spRunID)

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2"},
		Payload:   spPayloadWithTree(t, claim, tree, spAuthor, spAuthor),
	})
	if err == nil {
		t.Fatal("want a refusal when the ledger cannot append commit_intent")
	}
	if got := sc.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
		t.Errorf("%d commit_intent event(s) recorded as durable; the append itself failed", len(got))
	}
}

func TestPhaseARefusesWhenTheAppendedIntentCarriesNoEventID(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc, _, tree := spWiringWithRepo(t, resolver)
	sc.ledger.mangle = func(f event.Fields) event.Fields {
		if f[event.FieldEventType] == event.EventTypeCommitIntent {
			delete(f, event.FieldEventID)
		}
		return f
	}
	claim := spClaim(spRunID)

	_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2"},
		Payload:   spPayloadWithTree(t, claim, tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), event.FieldEventID) {
		t.Fatalf("error = %v, want a refusal naming the missing %s", err, event.FieldEventID)
	}
}

// ---------------------------------------------------------------------------
// Phase B — a real gitsignSigners factory, misconfigured or pointed at
// nothing listening, so NewSigner's own construction check and the
// trust-material fetch each get their own case, without Docker.
// ---------------------------------------------------------------------------

func TestPhaseBRefusesWhenTheSignerCannotBeConstructed(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc, _, tree := spWiringWithRepo(t, resolver)
	// No Fulcio/Rekor URL at all: signing.NewSigner refuses at construction,
	// before any network call.
	sc.cfg.Signers = NewGitsignSigners(signing.Config{Author: signing.AuthorPolicy{AllowUnlinked: true}})
	restoreSC2, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("re-ConfigureSignCommit: %v", err)
	}
	defer restoreSC2()
	claim := spClaim(spRunID)

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2"},
		Payload:   spPayloadWithTree(t, claim, tree, spAuthor, spAuthor),
	})
	if err == nil || !strings.Contains(err.Error(), "no signer for run") {
		t.Fatalf("error = %v, want a refusal naming the signer construction failure", err)
	}
}

func TestPhaseBRefusesWhenSigstoreIsUnreachable(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc, _, tree := spWiringWithRepo(t, resolver)
	// A fake gitsign — never actually invoked, since the trust-material
	// fetch below fails first — so NewSigner's own construction check
	// (exec.LookPath) has a real, executable path to resolve. Well-formed
	// but unreachable Fulcio/Rekor URLs make the first thing SignPayload
	// does — the trust-material fetch — fail fast on a refused connection,
	// no Docker required.
	fakeGitsign := filepath.Join(t.TempDir(), "fake-gitsign")
	if err := os.WriteFile(fakeGitsign, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("writing a fake gitsign: %v", err)
	}
	sc.cfg.Signers = NewGitsignSigners(signing.Config{
		FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:1",
		Issuer: "http://spire-oidc:8080", GitsignPath: fakeGitsign,
		Author: signing.AuthorPolicy{AllowUnlinked: true},
	})
	restoreSC2, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("re-ConfigureSignCommit: %v", err)
	}
	defer restoreSC2()
	claim := spClaim(spRunID)

	_, err = SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2"},
		Payload:   spPayloadWithTree(t, claim, tree, spAuthor, spAuthor),
	})
	classified := Classify(err)
	if classified.Class != ClassSigningUnavailable && classified.Class != ClassTransparencyUnavailable {
		t.Fatalf("error class = %s, want SIGNING_UNAVAILABLE or TRANSPARENCY_UNAVAILABLE (err=%v)",
			classified.Class, err)
	}
	if recorded := sc.ledger.ofType(event.EventTypeCommitRecorded); len(recorded) != 0 {
		t.Errorf("%d commit_recorded event(s); Phase B never signed anything", len(recorded))
	}
}

// ---------------------------------------------------------------------------
// Phase C — a REAL signature (real SPIRE, real Fulcio, real Rekor), with the
// ledger refusing only the commit_recorded append. No Postgres is needed
// here: the fake ledger (scLedger) plays both roles get_credential and
// sign_commit need, so this is the one Phase C case that does not pay
// requirePG's cost on top of the stack's.
// ---------------------------------------------------------------------------

func TestPhaseCRefusesWhenTheLedgerCannotAppendCommitRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := dockerUsable(ctx); err != nil {
		requireStartup(t, err, "this case proves Phase C's own refusal against a REAL "+
			"signature; a fake Fulcio would prove nothing about what it is refusing to record.")
	}
	stack, err := scStartStack(ctx, credRepoRoot(t))
	if stack != nil {
		t.Cleanup(stack.stop)
	}
	if err != nil {
		requireStartup(t, fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w", err),
			fmt.Sprintf("Start Docker, `go install github.com/sigstore/gitsign@%s`, and re-run.",
				scHarnessGitsignVersion))
	}

	const runID = "run-cmt241-phasec"
	spiffeID := fmt.Sprintf("spiffe://%s/agent/demo/%s/%s", scHarnessTrustDomain, spTaskID, runID)
	runs := cmtRuns{runID: {RunID: runID, AgentType: "demo", TaskID: spTaskID, SPIFFEID: spiffeID, Repo: spRepo}}

	repo, tree := spLocalRepo(t)

	fakeLedger := newSCLedger(nil)
	fakeLedger.failOn[event.EventTypeCommitRecorded] = errors.New("the chain is unreachable")

	if cerr := ConfigureGetCredential(CredentialConfig{
		Runs: runs, Entries: scOpenEntries{}, Ledger: fakeLedger,
		Minter: scStackMinter{stack: stack, ttl: 5 * time.Minute},
	}); cerr != nil {
		t.Fatalf("ConfigureGetCredential: %v", cerr)
	}

	sigstore, err := NewSigstoreEndpoints(SigstoreConfig{FulcioURL: stack.fulcioURL, RekorURL: stack.rekorURL})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	idem, _ := newStore(t)
	restoreSC, err := ConfigureSignCommit(SignCommitConfig{
		Runs: runs, Ledger: fakeLedger, Idempotency: idem, Workspace: fakeWorkspaceAt{dir: repo},
		Sigstore: sigstore, Credentials: SignCommitThroughGetCredential{},
		Signers: NewGitsignSigners(signing.Config{
			FulcioURL: stack.fulcioURL, RekorURL: stack.rekorURL, Issuer: scHarnessIssuer,
			GitsignPath: stack.gitsignPath, Author: signing.AuthorPolicy{AllowUnlinked: true},
		}),
		AuthorName: scAuthorName, AuthorEmail: scAuthorEmail, Pseudonyms: scLiteral(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()

	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(runID),
	}}
	claim := signing.Claim{Identity: spiffeID, Run: runID, Task: spTaskRef}
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{
		Resolver: resolver,
		ClaimFor: func(context.Context, string) (signing.Claim, error) { return claim, nil },
	})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	_, err = SignPayloadForGateway(ctx, commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Args:      []string{"--status-fd=2", "-bsau", scAuthorName + " <" + scAuthorEmail + ">"},
		Payload:   spPayloadWithTree(t, claim, tree, scAuthorEmail, scAuthorEmail),
	})
	if err == nil {
		t.Fatal("want a refusal: the ledger refuses the commit_recorded append")
	}
	if recorded := fakeLedger.ofType(event.EventTypeCommitRecorded); len(recorded) != 0 {
		t.Errorf("%d commit_recorded event(s) recorded as durable; the append itself failed", len(recorded))
	}
	intents := fakeLedger.ofType(event.EventTypeCommitIntent)
	if len(intents) != 1 {
		t.Fatalf("%d commit_intent events, want exactly 1: Phase A must have completed for "+
			"Phase C to have anything to refuse recording", len(intents))
	}
}

// fakeWorkspaceAt resolves every repo to the same fixed directory — this
// case has exactly one repository and no reason to check the argument.
type fakeWorkspaceAt struct{ dir string }

func (w fakeWorkspaceAt) Worktree(context.Context, string) (string, error) { return w.dir, nil }

// ---------------------------------------------------------------------------
// CMT-010 (I) and CMT-012 (I) — against real SPIRE, real Fulcio, real Rekor
// and a real chain: the commit-sign path's gates, Phase A, Phase B and
// Phase C, driven the way ADR-0059 decision 4 is actually reached — no
// svc.sign, no direct construction of a signCommitService, only
// SignPayloadForGateway and the package's own configuration entry points.
//
// One top-level case with the stack's lifetime, for TestSIG001's own reason
// (sign_commit_test.go): Go allows one heavy stack-owning test per run of
// this binary to run cleanly in sequence with the others, and splitting the
// two IDs into two such tests would pay for a second stack to prove a
// property this one already has everything on hand for.
//
//nolint:gocyclo // One assertion per fact, and every fact is measured.
func TestCMT010AndCMT012AgainstRealSigstoreAndARealChain(t *testing.T) {
	requirePG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		requireStartup(t, err, "CMT-010/CMT-012 prove nothing about I2, I3 or I5 "+
			"against a mock — IP §2, \"a mocked Fulcio proves nothing about I5\".")
	}
	stack, err := scStartStack(ctx, credRepoRoot(t))
	if stack != nil {
		t.Cleanup(stack.stop)
	}
	if err != nil {
		requireStartup(t, fmt.Errorf("bringing up the SPIRE and Sigstore stacks: %w", err),
			fmt.Sprintf("The commit-sign path goes unproven against a real signature. "+
				"Start Docker, `go install github.com/sigstore/gitsign@%s`, and re-run.",
				scHarnessGitsignVersion))
	}

	dsn := freshDSN(t, requirePG(t))
	migrate(t, dsn)
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)

	const (
		agentType = "demo"
		taskRef   = "RM-241"
		taskID    = "rm-241"
		repo      = "github.com/innsegl/cmt241"
	)

	// ---- a real repository, with one staged file ---------------------------
	root := t.TempDir()
	worktree := filepath.Join(root, filepath.FromSlash(repo))
	if merr := os.MkdirAll(worktree, 0o700); merr != nil {
		t.Fatal(merr)
	}
	scGit(t, worktree, "init", "-q", "-b", "main")
	scStage(t, worktree, "work.txt", "innsegl RM-241 CMT-010/012\n")
	tree := scGit(t, worktree, "write-tree")

	// ---- N runs, registered on the real chain -------------------------------
	runs := cmtRuns{}
	seed := func(n int) (runID, toolUseID string) {
		runID = fmt.Sprintf("run-cmt241-%02d", n)
		spiffeID := fmt.Sprintf("spiffe://%s/agent/%s/%s/%s", scHarnessTrustDomain, agentType, taskID, runID)
		registered, aerr := store.Append(ctx, event.Fields{
			event.FieldSchemaVersion:  event.SchemaVersion,
			event.FieldEventType:      event.EventTypeRunRegistered,
			event.FieldSource:         event.SourceMCP,
			event.FieldRunID:          runID,
			event.FieldSpiffeID:       spiffeID,
			event.FieldIdempotencyKey: "cmt241-register-" + runID,
			event.FieldAgentType:      agentType,
			event.FieldTaskRef:        taskRef,
			event.FieldRepo:           repo,
			event.FieldBranch:         "main",
		})
		if aerr != nil {
			t.Fatalf("seed run_registered for %s: %v", runID, aerr)
		}
		runs[runID] = CredentialRun{
			RunID:     runID,
			AgentType: scMember[string](t, registered, event.FieldAgentType),
			TaskID:    strings.ToLower(scMember[string](t, registered, event.FieldTaskRef)),
			SPIFFEID:  scMember[string](t, registered, event.FieldSpiffeID),
			Repo:      scMember[string](t, registered, event.FieldRepo),
		}
		// toolu_ + run id + enough padding to clear commitpath.IsToolUseID's
		// length floor, all in its accepted alphabet.
		toolUseID = "toolu_01cmt241" + strings.ReplaceAll(runID, "-", "") + "000000000000"
		return runID, toolUseID
	}

	// ---- the shipped get_credential, on the real SPIRE ---------------------
	if cerr := ConfigureGetCredential(CredentialConfig{
		Runs:    runs,
		Entries: scOpenEntries{},
		Minter:  scStackMinter{stack: stack, ttl: 5 * time.Minute},
		Ledger:  store,
	}); cerr != nil {
		t.Fatalf("ConfigureGetCredential: %v", cerr)
	}

	// ---- sign_commit's own configured service, reused by the commit-sign path
	workspace, err := NewWorkspace(root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	sigstore, err := NewSigstoreEndpoints(SigstoreConfig{FulcioURL: stack.fulcioURL, RekorURL: stack.rekorURL})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	idem, _ := newStore(t)
	restoreSC, err := ConfigureSignCommit(SignCommitConfig{
		Runs:        runs,
		Ledger:      store,
		Idempotency: idem,
		Workspace:   workspace,
		Sigstore:    sigstore,
		Credentials: SignCommitThroughGetCredential{},
		Signers: NewGitsignSigners(signing.Config{
			FulcioURL:   stack.fulcioURL,
			RekorURL:    stack.rekorURL,
			Issuer:      scHarnessIssuer,
			GitsignPath: stack.gitsignPath,
			Author:      signing.AuthorPolicy{AllowUnlinked: true},
		}),
		AuthorName:  scAuthorName,
		AuthorEmail: scAuthorEmail,
		Pseudonyms:  scLiteral(t),
	})
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	t.Cleanup(restoreSC)

	// ---- the commit-sign path's own two dependencies ------------------------
	resolver := &cmtResolver{calls: map[string]commitpath.RelayedCall{}}
	claimFor := func(_ context.Context, runID string) (signing.Claim, error) {
		run, ok := runs[runID]
		if !ok {
			return signing.Claim{}, fmt.Errorf("no run %q", runID)
		}
		return signing.Claim{Identity: run.SPIFFEID, Run: runID, Task: taskRef}, nil
	}
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: claimFor})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	t.Cleanup(restoreSP)

	args := []string{"--status-fd=2", "-bsau", scAuthorName + " <" + scAuthorEmail + ">"}
	buildPayload := func(claim signing.Claim, message string) []byte {
		trailers, terr := claim.Trailers()
		if terr != nil {
			t.Fatalf("claim.Trailers: %v", terr)
		}
		var b strings.Builder
		b.WriteString(message)
		b.WriteString("\n\n")
		for _, tr := range trailers {
			b.WriteString(tr.String())
			b.WriteString("\n")
		}
		ts := strconv.FormatInt(time.Now().UnixNano(), 10)[:10]
		return []byte(fmt.Sprintf(
			"tree %s\nauthor %s <%s> %s +0000\ncommitter %s <%s> %s +0000\n\n%s",
			tree, scAuthorName, scAuthorEmail, ts, scAuthorName, scAuthorEmail, ts, b.String()))
	}
	relay := func(runID, toolUseID string) {
		resolver.set(toolUseID, commitpath.RelayedCall{
			RunID: runID, Tool: "Bash",
			// The literal command text is the SAME for every run below —
			// CMT-012's own premise (ADR-0059's "byte-identical `git commit`
			// command"). Disambiguation has to come from the tool call id,
			// never from this string.
			Input:      json.RawMessage(`{"command":"git commit -m x"}`),
			ObservedAt: time.Now(),
		})
	}

	// ---- CMT-010: one valid payload -----------------------------------------
	t.Run("CMT-010 a valid payload", func(t *testing.T) {
		runID, toolUseID := seed(1)
		relay(runID, toolUseID)
		claim := signing.Claim{Identity: runs[runID].SPIFFEID, Run: runID, Task: taskRef}
		payload := buildPayload(claim, "CMT-010: a payload signed through the commit-sign path")

		resp, serr := SignPayloadForGateway(ctx, commitpath.SignRequest{
			ToolUseID: toolUseID, Args: args, Payload: payload,
		})
		if serr != nil {
			t.Fatalf("SignPayloadForGateway: %v", serr)
		}
		if len(resp.Signature) == 0 {
			t.Fatal("SignPayloadForGateway returned no signature")
		}

		commitSHA := writeSignedPayload(t, worktree, payload, resp.Signature)
		requireChainProvesCommit(ctx, t, store, runID, commitSHA, tree)
	})

	// ---- CMT-012: N runs issuing the byte-identical git commit command,
	//      concurrently, in one repository -------------------------------------
	t.Run("CMT-012 N concurrent byte-identical git commit calls", func(t *testing.T) {
		const n = 3
		type seeded struct{ runID, toolUseID string }
		var seededRuns [n]seeded
		for i := range seededRuns {
			runID, toolUseID := seed(100 + i)
			relay(runID, toolUseID)
			seededRuns[i] = seeded{runID, toolUseID}
		}

		type outcome struct {
			runID     string
			commitSHA string
			err       error
		}
		results := make([]outcome, n)
		var wg sync.WaitGroup
		for i, sr := range seededRuns {
			wg.Add(1)
			go func(i int, sr seeded) {
				defer wg.Done()
				claim := signing.Claim{Identity: runs[sr.runID].SPIFFEID, Run: sr.runID, Task: taskRef}
				payload := buildPayload(claim, fmt.Sprintf("CMT-012: run %s", sr.runID))
				resp, serr := SignPayloadForGateway(ctx, commitpath.SignRequest{
					ToolUseID: sr.toolUseID, Args: args, Payload: payload,
				})
				if serr != nil {
					results[i] = outcome{runID: sr.runID, err: serr}
					return
				}
				sha := writeSignedPayload(t, worktree, payload, resp.Signature)
				results[i] = outcome{runID: sr.runID, commitSHA: sha}
			}(i, sr)
		}
		wg.Wait()

		seen := map[string]string{} // commitSHA -> runID
		for _, r := range results {
			if r.err != nil {
				t.Errorf("run %s: %v", r.runID, r.err)
				continue
			}
			if other, dup := seen[r.commitSHA]; dup {
				t.Errorf("commit %s was attributed to both %s and %s", r.commitSHA, other, r.runID)
			}
			seen[r.commitSHA] = r.runID
			requireChainProvesCommit(ctx, t, store, r.runID, r.commitSHA, tree)
		}
		if len(seen) != n {
			t.Errorf("%d distinct signed commits, want %d — each run must be signed under "+
				"its own identity even though every one of them ran the same `git commit` "+
				"command at the same moment (ADR-0059)", len(seen), n)
		}
	})
}

// cmtRuns is CredentialRuns and CredentialRuns for CMT-010/012's several
// seeded runs — scChainRuns (sign_commit_test.go) holds exactly one and is
// not reused here for that reason.
type cmtRuns map[string]CredentialRun

func (r cmtRuns) CredentialRun(_ context.Context, runID string) (CredentialRun, bool, error) {
	run, ok := r[runID]
	return run, ok, nil
}

// cmtResolver is commitpath.Resolver, safe for concurrent use — CMT-012
// relays N tool calls before signing any of them, and gate 1 reads it from N
// goroutines at once.
type cmtResolver struct {
	mu    sync.Mutex
	calls map[string]commitpath.RelayedCall
}

func (r *cmtResolver) set(toolUseID string, call commitpath.RelayedCall) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[toolUseID] = call
}

func (r *cmtResolver) LookupPending(toolUseID string) (commitpath.RelayedCall, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.calls[toolUseID]
	return c, ok
}

// writeSignedPayload reconstructs the signed commit object exactly as
// signing.SignPayload's own commitSHAOf computes its id (internal/signing's
// TestSIGPAYLOAD001 proves that arithmetic against real git directly; this
// is the same construction, used here to hand the object to git itself for
// an independent second opinion) and writes it into worktree's object
// database, returning the id GIT ITSELF assigned it.
func writeSignedPayload(t *testing.T, worktree string, payload, signature []byte) string {
	t.Helper()
	idx := strings.Index(string(payload), "\n\n")
	if idx < 0 {
		t.Fatalf("payload carries no header/message separator")
	}
	header, message := payload[:idx], payload[idx+2:]
	sig := strings.TrimRight(string(signature), "\n")
	lines := strings.Split(sig, "\n")

	var body strings.Builder
	body.Write(header)
	body.WriteString("\ngpgsig " + lines[0] + "\n")
	for _, line := range lines[1:] {
		body.WriteString(" " + line + "\n")
	}
	body.WriteString("\n")
	body.Write(message)

	cmd := exec.CommandContext(t.Context(), "git", "-C", worktree,
		"hash-object", "-w", "-t", "commit", "--stdin")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(worktree, "nonexistent-gitconfig"))
	cmd.Stdin = strings.NewReader(body.String())
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object -w -t commit: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// requireChainProvesCommit reads runID's own events back off the real chain
// and requires the two-phase protocol's record of commitSHA: a commit_intent
// naming tree, a commit_recorded naming commitSHA and referencing the
// intent, and nothing of either type belonging to a DIFFERENT run claiming
// the same commit.
func requireChainProvesCommit(
	ctx context.Context, t *testing.T, store *ledger.Store, runID, commitSHA, tree string,
) {
	t.Helper()
	chain, err := store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun(%s): %v", runID, err)
	}
	var intent, recorded event.Fields
	for _, rec := range chain {
		switch scMember[string](t, rec, event.FieldEventType) {
		case event.EventTypeCommitIntent:
			intent = rec
		case event.EventTypeCommitRecorded:
			recorded = rec
		}
	}
	if intent == nil {
		t.Fatalf("run %s: no commit_intent on the chain", runID)
	}
	if recorded == nil {
		t.Fatalf("run %s: no commit_recorded on the chain", runID)
	}
	if got := scMember[string](t, intent, event.FieldTreeHash); got != tree {
		t.Errorf("run %s: commit_intent tree_hash = %s, want %s", runID, got, tree)
	}
	if got := scMember[string](t, recorded, event.FieldCommitSHA); got != commitSHA {
		t.Errorf("run %s: commit_recorded commit_sha = %s, want %s", runID, got, commitSHA)
	}
	if got := scMember[string](t, recorded, event.FieldIntentEventID); got != scMember[string](t, intent, event.FieldEventID) {
		t.Errorf("run %s: commit_recorded does not reference this run's own commit_intent", runID)
	}
}

// One Bash call can make more than one commit: an amend after a commit, or a
// retry after losing git's ref lock. Each is its own signature, so each must
// get its own intent and its own commit_recorded; a key from the tool call id
// alone made the second collapse onto the first's events and go unrecorded.
func TestCommitPathPhaseKeyIsOnePerPayloadOfOneToolCall(t *testing.T) {
	first := commitPathPhaseKey(commitPathIntentKeyPrefix, spToolUseID, []byte("tree a\n\nfirst\n"))
	again := commitPathPhaseKey(commitPathIntentKeyPrefix, spToolUseID, []byte("tree a\n\nfirst\n"))
	second := commitPathPhaseKey(commitPathIntentKeyPrefix, spToolUseID, []byte("tree b\n\nsecond\n"))
	other := commitPathPhaseKey(commitPathIntentKeyPrefix, spToolUseID+"x", []byte("tree a\n\nfirst\n"))
	if first != again {
		t.Errorf("one payload replayed gave two keys: %q, %q", first, again)
	}
	if first == second {
		t.Errorf("two payloads of one tool call share the key %q", first)
	}
	if first == other {
		t.Errorf("one payload under two tool calls shares the key %q", first)
	}
	if len(first) > 128 {
		t.Errorf("key is %d bytes, over the ledger's 128", len(first))
	}
}

// The commit's objects are read from the repository the agent works in, as
// its relayed request stated it, and only once that directory is proven to
// be the run's own repository: a stated directory is a claim.
func TestCommitPathWorktreeIsTheAgentsOwnRepositoryOnly(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q", dir}, {"-C", dir, "remote", "add", "origin", "https://github.com/example-org/example-repo.git"}} {
		if out, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	notARepo := t.TempDir()

	got, err := commitPathWorktree(t.Context(), dir, "github.com/example-org/example-repo")
	if err != nil || got != dir {
		t.Errorf("the run's own repository: got %q, %v; want %q", got, err, dir)
	}
	if _, err := commitPathWorktree(t.Context(), dir, "github.com/example-org/other-repo"); err == nil ||
		!strings.Contains(err.Error(), "not the run's repository") {
		t.Errorf("another repository was accepted: %v", err)
	}
	if _, err := commitPathWorktree(t.Context(), notARepo, "github.com/example-org/example-repo"); err == nil {
		t.Error("a directory with no repository was accepted")
	}
	if _, err := commitPathWorktree(t.Context(), "", "github.com/example-org/example-repo"); err == nil {
		t.Error("an empty working directory was accepted")
	}
}

// get_credential requires the run's own token where the deployment keys one
// (RM-212). The commit path has no caller holding it: the relayed tool call
// is what authorised this commit, so the core presents the token it derives
// for that run. A live agent commit was refused as "no run" without it.
func TestGate4PresentsTheRunsOwnTokenForTheCredential(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{
		spToolUseID: spPendingGitCommit(spRunID),
	}}
	sc := newSCWiring()
	sc.runs.run = CredentialRun{
		RunID: spRunID, AgentType: "demo", TaskID: spTaskID,
		SPIFFEID: spSPIFFEID(spRunID), Repo: spRepo,
	}
	sc.creds.err = errors.New("stop after the credential")
	sc.cfg.RunTokenSecret = "a-run-token-secret"
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	defer restoreSC()
	restoreSP, err := ConfigureSignPayload(SignPayloadConfig{Resolver: resolver, ClaimFor: spClaimForOK(t)})
	if err != nil {
		t.Fatalf("ConfigureSignPayload: %v", err)
	}
	defer restoreSP()

	if _, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID,
		Payload:   spPayload(t, spClaim(spRunID), spAuthor, spAuthor),
	}); err == nil {
		t.Fatal("want the stubbed credential refusal")
	}
	sc.creds.mu.Lock()
	defer sc.creds.mu.Unlock()
	if want := RunToken("a-run-token-secret", spRunID); sc.creds.token != want || want == "" {
		t.Errorf("the credential was asked with token %q, want the run's own %q", sc.creds.token, want)
	}
}

// spWiringSigningWith is spWiringWithRepo with a real gitsign signer factory
// (a fake gitsign binary, so NewSigner constructs) and Phase B's signing step
// replaced by sign, so Phases B and C run without Sigstore.
func spWiringSigningWith(t *testing.T, resolver spResolver,
	sign func(context.Context, *signing.Signer, signing.PayloadRequest) (signing.PayloadResult, error),
) (w *scWiring, repo, tree string) {
	t.Helper()
	sc, repo, tree := spWiringWithRepo(t, resolver)
	fakeGitsign := filepath.Join(t.TempDir(), "fake-gitsign")
	if err := os.WriteFile(fakeGitsign, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatalf("writing a fake gitsign: %v", err)
	}
	sc.cfg.Signers = NewGitsignSigners(signing.Config{
		FulcioURL: "http://127.0.0.1:1", RekorURL: "http://127.0.0.1:1",
		Issuer: "http://spire-oidc:8080", GitsignPath: fakeGitsign,
		Author: signing.AuthorPolicy{AllowUnlinked: true},
	})
	restoreSC, err := ConfigureSignCommit(sc.cfg)
	if err != nil {
		t.Fatalf("re-ConfigureSignCommit: %v", err)
	}
	t.Cleanup(restoreSC)
	signPayloadMu.Lock()
	st := *signPayloadCfg
	st.sign = sign
	previous := signPayloadCfg
	signPayloadCfg = &st
	signPayloadMu.Unlock()
	t.Cleanup(func() { signPayloadMu.Lock(); signPayloadCfg = previous; signPayloadMu.Unlock() })
	return sc, repo, tree
}

func spSignedOK(_ context.Context, _ *signing.Signer, _ signing.PayloadRequest) (signing.PayloadResult, error) {
	return signing.PayloadResult{
		Signature: []byte("SIG"), Status: []byte("[GNUPG:] SIG_CREATED \n"),
		CommitSHA: strings.Repeat("c", 40),
		Rekor:     signing.RekorEntry{LogIndex: 7, UUID: strings.Repeat("e", 80)},
	}, nil
}

// Phase B's signature reaches Phase C: commit_recorded carries the SHA and
// the Rekor entry, references the intent, and the caller gets the signature
// and status lines git needs.
func TestPhaseCRecordsTheSignedCommitAndAnswersTheSignature(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spPendingGitCommit(spRunID)}}
	sc, _, tree := spWiringSigningWith(t, resolver, spSignedOK)

	got, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Args: []string{"--status-fd=2", "-bsau", "k"},
		Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	})
	if err != nil {
		t.Fatalf("SignPayloadForGateway: %v", err)
	}
	if string(got.Signature) != "SIG" || !strings.Contains(string(got.Status), "SIG_CREATED") {
		t.Errorf("answer %+v", got)
	}
	recorded := sc.ledger.ofType(event.EventTypeCommitRecorded)
	if len(recorded) != 1 {
		t.Fatalf("%d commit_recorded, want 1", len(recorded))
	}
	if recorded[0][event.FieldCommitSHA] != strings.Repeat("c", 40) || recorded[0][event.FieldTreeHash] != tree {
		t.Errorf("commit_recorded %+v", recorded[0])
	}
}

// A ledger that takes the intent and refuses commit_recorded fails the call,
// so git writes no commit the chain has not recorded.
func TestPhaseCRefusesWhenCommitRecordedCannotBeAppended(t *testing.T) {
	resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: spPendingGitCommit(spRunID)}}
	sc, _, tree := spWiringSigningWith(t, resolver, spSignedOK)
	sc.ledger.failOn = map[string]error{event.EventTypeCommitRecorded: errors.New("ledger refused")}

	if _, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
		ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
	}); err == nil {
		t.Fatal("a commit_recorded the ledger refused still answered a signature")
	}
}

// The relayed call's stated working directory is used once it is proven to
// be the run's repository, and refused when it is not.
func TestSignPayloadUsesTheStatedWorkingDirectoryOnlyForTheRunsRepository(t *testing.T) {
	for _, tc := range []struct {
		name, origin string
		wantErr      bool
	}{
		{"the run's repository", "https://" + spRepo + ".git", false},
		{"another repository", "https://github.com/example-org/elsewhere.git", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call := spPendingGitCommit(spRunID)
			resolver := spResolver{calls: map[string]commitpath.RelayedCall{spToolUseID: call}}
			sc, repo, tree := spWiringSigningWith(t, resolver, spSignedOK)
			sc.space.dir = t.TempDir() // the core's own workspace must not be what is read
			scGit(t, repo, "remote", "add", "origin", tc.origin)
			call.WorkingDirectory = repo
			resolver.calls[spToolUseID] = call

			_, err := SignPayloadForGateway(context.Background(), commitpath.SignRequest{
				ToolUseID: spToolUseID, Payload: spPayloadWithTree(t, spClaim(spRunID), tree, spAuthor, spAuthor),
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}
