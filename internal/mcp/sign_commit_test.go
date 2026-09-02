// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/signing"
	"innsegl.dev/innsegl/internal/spire"
)

// RM-033 (#41) — sign_commit and the two-phase protocol.
//
// Test IDs: MCP-004 (schema conformance for sign_commit) and the ledger half
// of SIG-001 ("intent+recorded events in order").
//
// # The vacuity this file is written against
//
// "The intent was appended before the signature" passes if NEITHER happened.
// So every ordering assertion here goes through scPhases, which records what
// really ran, and requireTwoPhaseOrder both requires all three steps to be
// present and requires them in order. TestTheOrderAssertionBitesWhenThePhases-
// AreReversed feeds that same function a reversed transcript and FAILS if it
// is accepted — the assertion is itself under test.

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

const (
	scTrustDomain = "innsegl.dev"
	scAgentType   = "demo"
	scTaskRef     = "RM-033"
	scTaskID      = "rm-033"
	scRunID       = "run-rm033"
	scRepo        = "github.com/innsegl/innsegl"
	scStagedRef   = "0000000000000000000000000000000000000000"
	scTreeHash    = "1111111111111111111111111111111111111111"
	scCommitSHA   = "2222222222222222222222222222222222222222"
	scAuthorName  = "Innsegl Operator"
	scAuthorEmail = "operator@innsegl.invalid"
	scMessage     = "fix: the thing that was broken"
)

func scSPIFFEID() string {
	return "spiffe://" + scTrustDomain + "/agent/" + scAgentType + "/" + scTaskID + "/" + scRunID
}

func scRun() CredentialRun {
	return CredentialRun{
		RunID:     scRunID,
		AgentType: scAgentType,
		TaskID:    scTaskID,
		SPIFFEID:  scSPIFFEID(),
	}
}

func scIn() signCommitIn {
	return signCommitIn{
		RunID:          scRunID,
		Repo:           scRepo,
		StagedRef:      scStagedRef,
		Message:        scMessage,
		TaskRef:        scTaskRef,
		IdempotencyKey: "sc-key-1",
	}
}

// scPhases records what actually ran, in the order it ran.
type scPhases struct {
	mu    sync.Mutex
	steps []string
}

func (p *scPhases) record(step string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.steps = append(p.steps, step)
}

func (p *scPhases) all() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.steps)
}

// The three steps of IP §6.5, spelled once.
const (
	scStepIntent   = "A:append " + event.EventTypeCommitIntent
	scStepSign     = "B:sign"
	scStepRecorded = "C:append " + event.EventTypeCommitRecorded
)

// requireTwoPhaseOrder is SIG-001's ledger half as an assertion.
//
// It refuses a transcript in which any of the three steps is MISSING, which is
// what makes it non-vacuous, and refuses one in which they are out of order,
// which is what makes it the two-phase protocol rather than three unrelated
// facts. It returns an error rather than calling t.Fatal so that a test can
// assert it bites (TestTheOrderAssertionBitesWhenThePhasesAreReversed).
func requireTwoPhaseOrder(steps []string) error {
	want := []string{scStepIntent, scStepSign, scStepRecorded}
	at := func(step string) int { return slices.Index(steps, step) }
	for _, step := range want {
		if at(step) < 0 {
			return fmt.Errorf("%q never happened; transcript was %v", step, steps)
		}
	}
	if at(scStepIntent) >= at(scStepSign) || at(scStepSign) >= at(scStepRecorded) {
		return fmt.Errorf("the phases did not run A -> B -> C; transcript was %v", steps)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Fakes.
// ---------------------------------------------------------------------------

// scLedger is an append-only chain that behaves the way internal/ledger does
// in the two respects this tool depends on: it assigns event_id and
// chain_position, and an idempotency_key that has already been used returns
// the ORIGINAL event and writes nothing (LED-008).
type scLedger struct {
	phases *scPhases

	mu       sync.Mutex
	records  []event.Fields
	byKey    map[string]event.Fields
	position int64

	// failOn maps an event_type to the error Append returns for it.
	failOn map[string]error
	// mangle rewrites the record Append is about to return.
	mangle func(event.Fields) event.Fields
}

func newSCLedger(p *scPhases) *scLedger {
	return &scLedger{phases: p, byKey: map[string]event.Fields{}, failOn: map[string]error{}}
}

func (l *scLedger) Append(_ context.Context, body event.Fields) (event.Fields, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	eventType, _ := body[event.FieldEventType].(string) //nolint:errcheck // absent reads as ""
	// Recorded BEFORE the injected failure: a transcript has to show what was
	// attempted, or "the signer never ran" would be satisfied by a tool that
	// never tried to append either.
	if l.phases != nil {
		switch eventType {
		case event.EventTypeCommitIntent:
			l.phases.record(scStepIntent)
		case event.EventTypeCommitRecorded:
			l.phases.record(scStepRecorded)
		default:
			l.phases.record("?:append " + eventType)
		}
	}
	if err := l.failOn[eventType]; err != nil {
		return nil, err
	}
	key, _ := body[event.FieldIdempotencyKey].(string) //nolint:errcheck // absent reads as ""
	if original, seen := l.byKey[key]; seen && key != "" {
		return original.Clone(), nil
	}

	l.position++
	record := body.Clone()
	record[event.FieldEventID] = uuid.Must(uuid.NewV7()).String()
	record[event.FieldChainPosition] = l.position
	record[event.FieldTS] = event.NewTimestamp(time.Now()).String()
	if l.mangle != nil {
		record = l.mangle(record)
	}
	l.records = append(l.records, record)
	if key != "" {
		l.byKey[key] = record
	}
	return record.Clone(), nil
}

// ofType returns every appended record of one event type.
func (l *scLedger) ofType(eventType string) []event.Fields {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []event.Fields
	for _, r := range l.records {
		if got, _ := r[event.FieldEventType].(string); got == eventType { //nolint:errcheck // absent reads as ""
			out = append(out, r)
		}
	}
	return out
}

func (l *scLedger) only(t *testing.T, eventType string) event.Fields {
	t.Helper()
	got := l.ofType(eventType)
	if len(got) != 1 {
		t.Fatalf("the chain holds %d %s events, want exactly 1", len(got), eventType)
	}
	return got[0]
}

// scMember reads one member of a record, insisting on its type. A record that
// does not carry what the schema requires is a defect, not a zero value.
func scMember[T any](t *testing.T, rec event.Fields, name string) T {
	t.Helper()
	raw, present := rec[name]
	if !present {
		t.Fatalf("the record carries no %s: %v", name, rec)
	}
	value, ok := raw.(T)
	if !ok {
		t.Fatalf("the record's %s is %T, want %T", name, raw, value)
	}
	return value
}

// scRuns is the run directory.
type scRuns struct {
	run   CredentialRun
	found bool
	err   error
}

func (r scRuns) CredentialRun(context.Context, string) (CredentialRun, bool, error) {
	return r.run, r.found, r.err
}

// scWorkspace resolves host/org/name to a directory.
type scWorkspace struct {
	dir string
	err error
}

func (w scWorkspace) Worktree(context.Context, string) (string, error) { return w.dir, w.err }

// scRepos is the git plumbing reader.
type scRepos struct {
	tree       string
	stagedErr  error
	commitTree string
	commitErr  error
}

func (r scRepos) StagedTree(context.Context, string, string) (string, error) {
	return r.tree, r.stagedErr
}

func (r scRepos) CommitTree(context.Context, string, string) (string, error) {
	if r.commitTree == "" && r.commitErr == nil {
		return r.tree, nil
	}
	return r.commitTree, r.commitErr
}

// scCredentials is get_credential, as sign_commit sees it.
type scCredentials struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (c *scCredentials) IssueForSigning(_ context.Context, run CredentialRun) (signing.Credential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.err != nil {
		return signing.Credential{}, c.err
	}
	return signing.Credential{
		Token:     "test-token",
		SPIFFEID:  run.SPIFFEID,
		Audience:  AudienceSigstore,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}, nil
}

// scSigner is the gitsign wrapper.
type scSigner struct {
	phases *scPhases

	mu     sync.Mutex
	calls  int
	closed int
	reqs   []signing.Request

	err    error
	result *signing.Result
	// onSign runs at the moment of signing, so a case can change the world
	// between Phase A and the failure it is about.
	onSign func()
	// credentialCalls asks the source for a credential this many times.
	credentialCalls int
	src             signing.CredentialSource
}

func (s *scSigner) Sign(ctx context.Context, req signing.Request) (signing.Result, error) {
	s.mu.Lock()
	s.calls++
	s.reqs = append(s.reqs, req)
	s.mu.Unlock()
	if s.phases != nil {
		s.phases.record(scStepSign)
	}
	if s.onSign != nil {
		s.onSign()
	}
	for i := 0; i < s.credentialCalls; i++ {
		if _, err := s.src.Credential(ctx); err != nil {
			return signing.Result{}, err
		}
	}
	if s.err != nil {
		return signing.Result{}, s.err
	}
	if s.result != nil {
		return *s.result, nil
	}
	trailers, err := req.Claim.Trailers()
	if err != nil {
		return signing.Result{}, err
	}
	return signing.Result{
		CommitSHA: scCommitSHA,
		Trailers:  trailers,
		Rekor: signing.RekorEntry{
			UUID:         "24296fb24b8ad77a" + strings.Repeat("ab", 32),
			LogIndex:     7,
			LogID:        "c0d23d6a",
			IntegratedAt: time.Unix(1_756_000_000, 0).UTC(),
		},
		CredentialSPIFFEID: req.Claim.Identity,
		CredentialExpires:  time.Now().Add(4 * time.Minute),
	}, nil
}

func (s *scSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

// scSigners is the factory.
type scSigners struct {
	signer   *scSigner
	openErr  error
	admitErr error
	opens    int
}

func (f *scSigners) Admits(string) error { return f.admitErr }

func (f *scSigners) Open(src signing.CredentialSource) (SignCommitSigner, error) {
	f.opens++
	if f.openErr != nil {
		return nil, f.openErr
	}
	f.signer.src = src
	return f.signer, nil
}

// scSigstore is the ADR-0024 reachability probe. probeSigstore reaches both
// halves concurrently, so the record is guarded.
type scSigstore struct {
	mu           sync.Mutex
	signing      error
	transparency error
	probes       []string
}

func (s *scSigstore) ProbeSigning(context.Context) error {
	s.mu.Lock()
	s.probes = append(s.probes, "fulcio")
	s.mu.Unlock()
	return s.signing
}

func (s *scSigstore) ProbeTransparency(context.Context) error {
	s.mu.Lock()
	s.probes = append(s.probes, "rekor")
	s.mu.Unlock()
	return s.transparency
}

// scWiring is one fully wired sign_commit and the fakes behind it.
type scWiring struct {
	cfg     SignCommitConfig
	phases  *scPhases
	ledger  *scLedger
	runs    *scRuns
	repos   *scRepos
	space   *scWorkspace
	creds   *scCredentials
	signer  *scSigner
	signers *scSigners
	store   *scSigstore
}

// newSCWiring builds a sign_commit whose every dependency answers.
//
// The idempotency store is a real *IdempotencyStore over no pool: the cases
// below call the three phases directly, which is the whole tool minus the
// claim, and the claim needs a Postgres. TestTheClaimIsWhatStopsASecondCommit
// takes a real one from requirePG and drives the tool through it.
func newSCWiring() *scWiring {
	phases := &scPhases{}
	w := &scWiring{
		phases: phases,
		ledger: newSCLedger(phases),
		runs:   &scRuns{run: scRun(), found: true},
		repos:  &scRepos{tree: scTreeHash},
		space:  &scWorkspace{dir: "/tmp/innsegl-sc"},
		creds:  &scCredentials{},
		signer: &scSigner{phases: phases},
		store:  &scSigstore{},
	}
	w.signers = &scSigners{signer: w.signer}
	// Identity mode `literal`: this file's fixtures are scTaskRef "RM-033"
	// against scTaskID "rm-033", which is what `literal` produces and what
	// every assertion below is written in terms of. PRI-003 measures
	// `pseudonymous` end to end.
	literal, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		// newSCWiring has no *testing.T; a fixture that cannot be built is a
		// defect in the fixture, not a case outcome.
		panic("newSCWiring: " + err.Error())
	}
	w.cfg = SignCommitConfig{
		Runs:        w.runs,
		Idempotency: NewIdempotencyStore(nil),
		Ledger:      w.ledger,
		Workspace:   w.space,
		Repos:       w.repos,
		Sigstore:    w.store,
		Credentials: w.creds,
		Signers:     w.signers,
		AuthorName:  scAuthorName,
		AuthorEmail: scAuthorEmail,
		Pseudonyms:  literal,
	}
	return w
}

// service builds the configured tool without touching package state.
func (w *scWiring) service(t *testing.T) *signCommitService {
	t.Helper()
	svc, err := newSignCommitService(w.cfg)
	if err != nil {
		t.Fatalf("newSignCommitService: %v", err)
	}
	return svc
}

// call runs one sign_commit through the service, bypassing the claim.
func (w *scWiring) call(t *testing.T, in signCommitIn) (signCommitOut, error) {
	t.Helper()
	raw, err := w.service(t).phases(t.Context(), in)
	if err != nil {
		return signCommitOut{}, err
	}
	out, ok := raw.(signCommitOut)
	if !ok {
		t.Fatalf("the tool returned %T, want signCommitOut", raw)
	}
	return out, nil
}

// requireClass asserts the IP §4 class of a refusal.
func requireClass(t *testing.T, err error, want Class) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %s", want)
	}
	if got := Classify(err); got.Class != want {
		t.Fatalf("class is %s (%v), want %s", got.Class, err, want)
	}
}

// requireClassed does the same and hands back the structured error, for the
// cases that go on to assert `retryable` or the message.
func requireClassed(t *testing.T, err error, want Class) *Error {
	t.Helper()
	requireClass(t, err, want)
	return Classify(err)
}

// ---------------------------------------------------------------------------
// MCP-004 — schema conformance.
// ---------------------------------------------------------------------------

// TestMCP004SignCommitReturnsTheDocumentedResultShape.
//
// IP §4: sign_commit(run_id, repo, staged_ref, message, task_ref,
// idempotency_key) -> {commit_sha, rekor_entry, trailers}. The member names on
// the wire are the contract, so they are read off the marshalled JSON rather
// than off the Go struct.
func TestMCP004SignCommitReturnsTheDocumentedResultShape(t *testing.T) {
	w := newSCWiring()
	out, err := w.call(t, scIn())
	if err != nil {
		t.Fatalf("sign_commit: %v", err)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal the result: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal the result: %v", err)
	}
	wantMembers := []string{"commit_sha", "rekor_entry", "trailers"}
	if len(got) != len(wantMembers) {
		t.Errorf("the result has %d members (%s), want exactly %v", len(got), raw, wantMembers)
	}
	for _, name := range wantMembers {
		if _, present := got[name]; !present {
			t.Errorf("the result has no %q member: %s", name, raw)
		}
	}

	if out.CommitSHA != scCommitSHA {
		t.Errorf("commit_sha is %q, want %q", out.CommitSHA, scCommitSHA)
	}
	if out.RekorEntry.LogIndex != 7 || out.RekorEntry.UUID == "" {
		t.Errorf("rekor_entry is %+v, want the entry the signer reported", out.RekorEntry)
	}

	// The three protected trailer keys of IP §1, in IP §1 order.
	wantTrailers := []SignCommitTrailer{
		{Key: signing.TrailerAgentIdentity, Value: scSPIFFEID()},
		{Key: signing.TrailerAgentRun, Value: scRunID},
		{Key: signing.TrailerAgentTask, Value: scTaskRef},
	}
	if !slices.Equal(out.Trailers, wantTrailers) {
		t.Errorf("trailers are %+v, want %+v", out.Trailers, wantTrailers)
	}
}

// ---------------------------------------------------------------------------
// SIG-001, ledger half — intent + recorded, in order, linked.
// ---------------------------------------------------------------------------

// TestSIG001TheIntentIsAppendedBeforeTheSignatureAndTheRecordReferencesIt.
//
// doc 07 SIG-001: "intent+recorded events in order". IP §6.5 fixes what that
// means: Phase A appends `commit_intent` with the tree hash BEFORE any
// signing, Phase C appends `commit_recorded` referencing the intent.
func TestSIG001TheIntentIsAppendedBeforeTheSignatureAndTheRecordReferencesIt(t *testing.T) {
	w := newSCWiring()
	out, err := w.call(t, scIn())
	if err != nil {
		t.Fatalf("sign_commit: %v", err)
	}

	// Both really happened, and the signature happened between them.
	if err := requireTwoPhaseOrder(w.phases.all()); err != nil {
		t.Fatalf("the two-phase protocol did not run: %v", err)
	}

	intent := w.ledger.only(t, event.EventTypeCommitIntent)
	recorded := w.ledger.only(t, event.EventTypeCommitRecorded)

	// Phase A carries doc 02 §3's required members and nothing invented.
	if got := intent[event.FieldRepo]; got != scRepo {
		t.Errorf("commit_intent repo is %v, want %q", got, scRepo)
	}
	if got := intent[event.FieldTreeHash]; got != scTreeHash {
		t.Errorf("commit_intent tree_hash is %v, want %q", got, scTreeHash)
	}
	if got := intent[event.FieldSpiffeID]; got != scSPIFFEID() {
		t.Errorf("commit_intent spiffe_id is %v, want %q", got, scSPIFFEID())
	}
	if got := intent[event.FieldSource]; got != event.SourceMCP {
		t.Errorf("commit_intent source is %v, want %q", got, event.SourceMCP)
	}

	// Phase C carries the link. This is the assertion that makes the two
	// events one protocol rather than two coincidences.
	if got, want := recorded[event.FieldIntentEventID], intent[event.FieldEventID]; got != want {
		t.Fatalf("commit_recorded intent_event_id is %v, want the intent's event_id %v", got, want)
	}
	if got := recorded[event.FieldCommitSHA]; got != out.CommitSHA {
		t.Errorf("commit_recorded commit_sha is %v, want the returned %q", got, out.CommitSHA)
	}
	if got := recorded[event.FieldTreeHash]; got != scTreeHash {
		t.Errorf("commit_recorded tree_hash is %v, want the intent's %q", got, scTreeHash)
	}
	if got := recorded[event.FieldRekorLogIndex]; got != int64(7) {
		t.Errorf("commit_recorded rekor_log_index is %v, want 7", got)
	}
	if got := recorded[event.FieldRekorEntryUUID]; got != out.RekorEntry.UUID {
		t.Errorf("commit_recorded rekor_entry_uuid is %v, want %q", got, out.RekorEntry.UUID)
	}

	// Chain order, not merely append order.
	pa := scMember[int64](t, intent, event.FieldChainPosition)
	pc := scMember[int64](t, recorded, event.FieldChainPosition)
	if pa >= pc {
		t.Fatalf("commit_intent is at position %d and commit_recorded at %d; "+
			"the intent must precede the record", pa, pc)
	}

	// Both events must be appendable by the real ledger: the member set is
	// closed and doc 02 §3 requires exactly these.
	for _, rec := range []event.Fields{intent, recorded} {
		if err := rec.Validate(); err != nil {
			t.Errorf("%v is not a valid event: %v", rec[event.FieldEventType], err)
		}
	}
}

// TestTheOrderAssertionBitesWhenThePhasesAreReversed.
//
// The ordering assertion above is only worth anything if it FAILS on a
// transcript that violates it. Twelve vacuous passes have been caught on this
// project; this is the case that keeps the thirteenth out of this file.
func TestTheOrderAssertionBitesWhenThePhasesAreReversed(t *testing.T) {
	good := []string{scStepIntent, scStepSign, scStepRecorded}
	if err := requireTwoPhaseOrder(good); err != nil {
		t.Fatalf("the assertion rejected a correct transcript: %v", err)
	}

	for _, bad := range [][]string{
		{scStepSign, scStepIntent, scStepRecorded}, // signed before the intent
		{scStepIntent, scStepRecorded, scStepSign}, // recorded before the signature
		{scStepRecorded, scStepSign, scStepIntent}, // fully reversed
		{scStepIntent, scStepRecorded},             // nothing was signed
		{scStepSign, scStepRecorded},               // no intent at all
		{},                                         // the vacuous transcript
	} {
		if err := requireTwoPhaseOrder(bad); err == nil {
			t.Errorf("the assertion accepted %v; it does not bite", bad)
		}
	}
}

// TestTheSignatureIsNeverAskedForBeforeTheIntentIsRecorded drives the same
// property from the other side: the signer is handed the phase log, so a
// reordering of the implementation shows up as a reordered transcript.
func TestTheSignatureIsNeverAskedForBeforeTheIntentIsRecorded(t *testing.T) {
	w := newSCWiring()
	// The ledger refuses Phase A. If signing happened first, the signer would
	// have been called anyway.
	w.ledger.failOn[event.EventTypeCommitIntent] = errors.New("the chain is unreachable")

	if _, err := w.call(t, scIn()); err == nil {
		t.Fatal("sign_commit succeeded with no commit_intent recorded (I3)")
	}
	steps := w.phases.all()
	// Non-vacuity first: the tool must have REACHED Phase A. Without this the
	// two assertions below are satisfied by a tool that does nothing at all.
	if !slices.Contains(steps, scStepIntent) {
		t.Fatalf("Phase A was never attempted; transcript was %v", steps)
	}
	if w.signer.calls != 0 {
		t.Fatalf("the signer ran %d times after Phase A failed; IP §6.5 puts the "+
			"intent before ANY signing", w.signer.calls)
	}
	if slices.Contains(steps, scStepSign) {
		t.Fatalf("transcript %v contains a signature", steps)
	}
}

// ---------------------------------------------------------------------------
// IP §6.3 — fail closed on Sigstore.
// ---------------------------------------------------------------------------

// TestSigstoreIsProbedBeforePhaseAAndClassifiedPerHalf.
//
// IP §6.3 gives Fulcio and Rekor separate classes. The probe runs BEFORE
// Phase A, so an outage that is already visible does not leave a dangling
// intent behind for the reconciler to expire.
func TestSigstoreIsProbedBeforePhaseAAndClassifiedPerHalf(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  func(*scWiring)
		class Class
	}{
		{"fulcio down", func(w *scWiring) {
			w.store.signing = Errorf(ClassSigningUnavailable, "", "connection refused")
		}, ClassSigningUnavailable},
		{"rekor down", func(w *scWiring) {
			w.store.transparency = Errorf(ClassTransparencyUnavailable, "", "connection refused")
		}, ClassTransparencyUnavailable},
		{"both down", func(w *scWiring) {
			w.store.signing = Errorf(ClassSigningUnavailable, "", "connection refused")
			w.store.transparency = Errorf(ClassTransparencyUnavailable, "", "connection refused")
		}, ClassSigningUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			tc.wire(w)

			_, err := w.call(t, scIn())
			e := requireClassed(t, err, tc.class)
			if !e.Retryable {
				t.Errorf("%s must be retryable (IP §6.3)", e.Class)
			}
			if got := len(w.ledger.records); got != 0 {
				t.Errorf("%d events were appended; an outage visible before Phase A "+
					"must leave no dangling intent", got)
			}
			if w.signer.calls != 0 {
				t.Errorf("the signer ran %d times with Sigstore down", w.signer.calls)
			}
		})
	}
}

// TestASigstoreOutageDuringPhaseBLeavesTheIntentAndNoCommitRecorded.
//
// This is the A -> B window named exactly. The intent exists, the signature
// does not, and no `commit_recorded` was invented for a commit that was never
// created. RM-035's reconciler expires it (REC-001).
func TestASigstoreOutageDuringPhaseBLeavesTheIntentAndNoCommitRecorded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		class Class
	}{
		{"fulcio", signing.ErrSigningUnavailable, ClassSigningUnavailable},
		{"rekor", signing.ErrTransparencyUnavailable, ClassTransparencyUnavailable},
		{"credential", signing.ErrCredentialUnavailable, ClassCredentialExpired},
		{"gitsign refused", signing.ErrSigning, ClassInvariantViolation},
		{"identity mismatch", signing.ErrIdentityMismatch, ClassInvariantViolation},
		{"unreadable signature", signing.ErrSignature, ClassInvariantViolation},
		{"bad configuration", signing.ErrConfig, ClassInvariantViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			w.signer.err = fmt.Errorf("wrapped: %w", tc.err)

			_, err := w.call(t, scIn())
			requireClass(t, err, tc.class)

			if got := len(w.ledger.ofType(event.EventTypeCommitIntent)); got != 1 {
				t.Errorf("%d commit_intent events, want exactly 1: the intent is what "+
					"makes the failure recoverable (IP §6.5)", got)
			}
			if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 0 {
				t.Errorf("%d commit_recorded events for a commit that was never signed", got)
			}
			if w.signer.closed == 0 {
				t.Error("the signer was not closed; its work directory would leak")
			}
		})
	}
}

// TestAGitsignRefusalIsAttributedToWhicheverHalfOfSigstoreIsActuallyDown.
//
// ErrSigning is a subprocess exiting non-zero, and a Fulcio or Rekor outage
// that began after the pre-Phase-A probe reaches this layer wearing exactly
// that error. RM-034 measured the same thing from the other side (ADR-0032):
// a Rekor outage can arrive as ErrSigning, and reporting INVARIANT_VIOLATION
// would tell an operator their system has a defect when a dependency is down.
// So the dependency is asked, and its answer decides the class.
func TestAGitsignRefusalIsAttributedToWhicheverHalfOfSigstoreIsActuallyDown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  func(*scWiring)
		class Class
	}{
		{"fulcio died after the probe", func(w *scWiring) {
			w.store.signing = Errorf(ClassSigningUnavailable, "", "connection refused")
		}, ClassSigningUnavailable},
		{"rekor died after the probe", func(w *scWiring) {
			w.store.transparency = Errorf(ClassTransparencyUnavailable, "", "connection refused")
		}, ClassTransparencyUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			// The intent is appended first, so the outage has to begin AFTER
			// the pre-Phase-A probe: the signer is what turns it on.
			w.signer.err = fmt.Errorf("gitsign: %w", signing.ErrSigning)
			w.signer.onSign = func() { tc.wire(w) }

			_, err := w.call(t, scIn())
			e := requireClassed(t, err, tc.class)
			if !e.Retryable {
				t.Errorf("%s must be retryable (IP §6.3)", e.Class)
			}
			if got := len(w.ledger.ofType(event.EventTypeCommitIntent)); got != 1 {
				t.Errorf("%d commit_intent events; the outage began after Phase A", got)
			}
			if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 0 {
				t.Errorf("%d commit_recorded events for a commit that was never signed", got)
			}
		})
	}
}

// TestACredentialFailureAbortsBeforePhaseA is IP §6.1 in terms: "spire-agent
// socket lost mid-run at get_credential -> IDENTITY_UNAVAILABLE; any in-flight
// sign_commit aborts before Phase A (6.5)."
func TestACredentialFailureAbortsBeforePhaseA(t *testing.T) {
	w := newSCWiring()
	w.creds.err = Errorf(ClassIdentityUnavailable, scRunID, "the workload socket is gone")

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassIdentityUnavailable)

	if got := len(w.ledger.records); got != 0 {
		t.Fatalf("%d events were appended; IP §6.1 aborts BEFORE Phase A", got)
	}
	if w.signer.calls != 0 {
		t.Fatalf("the signer ran %d times with no credential", w.signer.calls)
	}
}

// TestTheCredentialIsFetchedOnceAndReFetchedOnlyWhenTheWrapperAsksAgain.
//
// The pre-fetch exists to satisfy IP §6.1's ordering, and it must not turn
// into a second issuance: the primed credential is what the wrapper is handed
// first. A wrapper that asks a second time gets a second issuance, which is
// IP §6.2's transparent re-fetch and is deliberately not suppressed.
func TestTheCredentialIsFetchedOnceAndReFetchedOnlyWhenTheWrapperAsksAgain(t *testing.T) {
	w := newSCWiring()
	w.signer.credentialCalls = 1
	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	if w.creds.calls != 1 {
		t.Fatalf("get_credential was called %d times, want 1", w.creds.calls)
	}

	w = newSCWiring()
	w.signer.credentialCalls = 2
	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	if w.creds.calls != 2 {
		t.Fatalf("get_credential was called %d times for two wrapper requests, want 2", w.creds.calls)
	}
}

// TestAReFetchFailureInsideTheWrapperIsReportedAsTheCredentialFailureItIs
// drives the source's second branch to its error.
func TestAReFetchFailureInsideTheWrapperIsReportedAsTheCredentialFailureItIs(t *testing.T) {
	w := newSCWiring()
	w.signer.credentialCalls = 2
	failAfter := 1
	base := w.creds
	w.cfg.Credentials = credFunc(func(ctx context.Context, run CredentialRun) (signing.Credential, error) {
		cred, err := base.IssueForSigning(ctx, run)
		if base.calls > failAfter {
			return signing.Credential{}, Errorf(ClassIdentityUnavailable, run.RunID, "gone")
		}
		return cred, err
	})

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassIdentityUnavailable)
}

// credFunc adapts a function to SignCommitCredentials.
type credFunc func(context.Context, CredentialRun) (signing.Credential, error)

func (f credFunc) IssueForSigning(ctx context.Context, run CredentialRun) (signing.Credential, error) {
	return f(ctx, run)
}

// ---------------------------------------------------------------------------
// The gates that run before Phase A.
// ---------------------------------------------------------------------------

func TestSignCommitRefusesAMalformedRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*signCommitIn)
		class Class
	}{
		{"no run id", func(in *signCommitIn) { in.RunID = "" }, ClassRunNotFound},
		{"run id that is not one", func(in *signCommitIn) { in.RunID = "Run 42" }, ClassRunNotFound},
		{"no repo", func(in *signCommitIn) { in.Repo = "" }, ClassInvariantViolation},
		{"repo that is not host/org/name", func(in *signCommitIn) { in.Repo = "innsegl" }, ClassInvariantViolation},
		{"no staged ref", func(in *signCommitIn) { in.StagedRef = "" }, ClassInvariantViolation},
		{"staged ref with a newline", func(in *signCommitIn) { in.StagedRef = "HEAD\nrm -rf" }, ClassInvariantViolation},
		{"staged ref that is an option", func(in *signCommitIn) { in.StagedRef = "--upload-pack=x" }, ClassInvariantViolation},
		{"no message", func(in *signCommitIn) { in.Message = "" }, ClassInvariantViolation},
		{"staged ref that is too long", func(in *signCommitIn) {
			in.StagedRef = strings.Repeat("a", event.MaxReferenceBytes+1)
		}, ClassInvariantViolation},
		{"message that is only whitespace", func(in *signCommitIn) { in.Message = "  \n " }, ClassInvariantViolation},
		{"message that is too long", func(in *signCommitIn) {
			in.Message = strings.Repeat("m", MaxSignCommitMessageBytes+1)
		}, ClassInvariantViolation},
		{"no task ref", func(in *signCommitIn) { in.TaskRef = "" }, ClassInvariantViolation},
		{"task ref that is too long", func(in *signCommitIn) {
			in.TaskRef = strings.Repeat("t", event.MaxReferenceBytes+1)
		}, ClassInvariantViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			in := scIn()
			tc.edit(&in)

			// The request gates run OUTSIDE the idempotency claim, so this is
			// the served entry point and not the phases: a malformed call must
			// cost nothing and reserve no key.
			_, err := w.service(t).sign(t.Context(), in)
			requireClass(t, err, tc.class)
			if got := len(w.ledger.records); got != 0 {
				t.Errorf("%d events were appended for a request that was refused", got)
			}
			if w.creds.calls != 0 {
				t.Errorf("a credential was spent on a request that was refused")
			}
		})
	}
}

// TestPRI003ATaskRefTheGrammarWillNotCarryIsRefusedBeforePhaseA. RM-079 (#116).
//
// `signCommitCheckRequest` bounds `task_ref` by emptiness and by
// event.MaxReferenceBytes (256) and NOT by doc 02 §5's identifier grammar. So a
// task reference with a slash in it, or one of 64 legal characters, passes the
// request gate and is refused one step later — where it is rendered into the
// Agent-Task trailer, which must lowercase to the identity's {task_id}.
//
// The first half of each case is the part that stops this test being vacuous:
// it asserts that the tool's own request gate ADMITS the value. Without that,
// a later tightening of signCommitCheckRequest would make this branch dead and
// the test would still pass, which is the shape IP §2's branch floor exists to
// catch.
//
// The class is asserted, not merely the failure: INVARIANT_VIOLATION and not
// retryable is what IP §4's vocabulary — a protected surface — says a malformed
// argument is, and it is what this input produced before RM-079 too, when
// signing.Claim.Trailers refused it one line further on.
func TestPRI003ATaskRefTheGrammarWillNotCarryIsRefusedBeforePhaseA(t *testing.T) {
	for _, tc := range []struct {
		name    string
		taskRef string
	}{
		{"a separator the grammar has no place for", "JIRA/118"},
		{"a space", "ACME 90210"},
		{"64 legal characters, one over the 63 the grammar allows", strings.Repeat("a", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := scIn()
			in.TaskRef = tc.taskRef

			// (1) The request gate admits it, so the refusal below is one this
			// tool can really reach.
			if err := signCommitCheckRequest(in); err != nil {
				t.Fatalf("signCommitCheckRequest rejected %q (%v), so the refusal this "+
					"case is about is unreachable and the case proves nothing",
					tc.taskRef, err)
			}

			// (2) And the tool refuses it, in IP §4's vocabulary.
			w := newSCWiring()
			_, err := w.call(t, in)
			if err == nil {
				t.Fatal("sign_commit accepted a task_ref the SPIFFE ID grammar cannot carry; " +
					"the Agent-Task trailer must lowercase to the identity's {task_id}")
			}
			classified := requireClassed(t, err, ClassInvariantViolation)
			if classified.Retryable {
				t.Errorf("the refusal is retryable; a malformed argument does not become "+
					"well formed on a retry (ADR-0016): %v", err)
			}

			// (3) Nothing durable happened. The refusal is before Phase A, so
			// there is no intent for the reconciler to resolve and no
			// credential was fetched.
			if got := w.ledger.ofType(event.EventTypeCommitIntent); len(got) != 0 {
				t.Errorf("the refused call appended %d commit_intent event(s); a refusal "+
					"before Phase A must leave the reconciler nothing to resolve", len(got))
			}
			if steps := w.phases.all(); len(steps) != 0 {
				t.Errorf("the refused call ran %v; it must refuse before any of them", steps)
			}
		})
	}
}

// TestSignCommitRefusesAClaimThisRunCannotMake.
//
// task_ref becomes the Agent-Task trailer and must lowercase to the task
// segment of the run's SPIFFE ID. The check is inside the claim, because it
// needs the run's identity — and it runs before the credential is spent and
// long before Phase A, so a claim this run cannot make leaves nothing behind.
func TestSignCommitRefusesAClaimThisRunCannotMake(t *testing.T) {
	w := newSCWiring()
	in := scIn()
	in.TaskRef = "OTHER-1"

	_, err := w.call(t, in)
	requireClass(t, err, ClassInvariantViolation)
	if got := len(w.ledger.records); got != 0 {
		t.Errorf("%d events were appended for a claim this run cannot make", got)
	}
	if w.creds.calls != 0 {
		t.Error("a credential was spent on a claim this run cannot make")
	}
}

func TestSignCommitRefusesARunItCannotSignFor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		wire  func(*scWiring)
		class Class
	}{
		{"unknown run", func(w *scWiring) { w.runs.found = false }, ClassRunNotFound},
		{"retired run", func(w *scWiring) {
			w.runs.run.RetiredAt = time.Unix(1_756_000_000, 0).UTC()
		}, ClassRunAlreadyRetired},
		{"the directory failed", func(w *scWiring) {
			w.runs.err = errors.New("the chain is unreachable")
		}, ClassInvariantViolation},
		{"the directory answered for another run", func(w *scWiring) {
			w.runs.run.RunID = "run-somebody-else"
		}, ClassInvariantViolation},
		{"the run has no usable identity", func(w *scWiring) {
			w.runs.run.SPIFFEID = "not-a-spiffe-id"
		}, ClassInvariantViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			tc.wire(w)

			_, err := w.call(t, scIn())
			requireClass(t, err, tc.class)
			if got := len(w.ledger.records); got != 0 {
				t.Errorf("%d events were appended for a run that cannot sign", got)
			}
		})
	}
}

func TestSignCommitRefusesARepositoryItCannotReach(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire func(*scWiring)
	}{
		{"the workspace has no such repo", func(w *scWiring) {
			w.space.err = errors.New("no working tree for github.com/innsegl/innsegl")
		}},
		{"the staged tree cannot be read", func(w *scWiring) {
			w.repos.stagedErr = errors.New("not a git repository")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			tc.wire(w)

			_, err := w.call(t, scIn())
			requireClass(t, err, ClassInvariantViolation)
			if got := len(w.ledger.records); got != 0 {
				t.Errorf("%d events were appended for a repository that could not be read", got)
			}
		})
	}
}

func TestSignCommitRefusesAStagedTreeThatIsNotAnObjectID(t *testing.T) {
	w := newSCWiring()
	w.repos.tree = "not-a-tree"

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassInvariantViolation)
	if got := len(w.ledger.records); got != 0 {
		t.Errorf("%d events were appended for a tree hash that is not one", got)
	}
}

func TestSignCommitRefusesASignerItCannotOpen(t *testing.T) {
	w := newSCWiring()
	w.signers.openErr = errors.New("gitsign is not on PATH")

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassInvariantViolation)
	if got := len(w.ledger.records); got != 0 {
		t.Errorf("%d events were appended with no signer to sign with", got)
	}
}

// ---------------------------------------------------------------------------
// The B -> C window, and what closes it.
// ---------------------------------------------------------------------------

// TestACommitWhoseTreeIsNotTheIntentsIsAnInvariantViolation.
//
// The commit is read back and compared with the tree Phase A recorded. A
// mismatch means the signature covers something other than what the ledger
// says was intended, which is not a retryable condition — it is the shape of
// failure IP §6.9 calls trailer spoofing, seen from inside.
func TestACommitWhoseTreeIsNotTheIntentsIsAnInvariantViolation(t *testing.T) {
	w := newSCWiring()
	w.repos.commitTree = "3333333333333333333333333333333333333333"

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassInvariantViolation)

	if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 0 {
		t.Errorf("%d commit_recorded events for a commit of the wrong tree", got)
	}
}

func TestACommitThatCannotBeReadBackIsAnInvariantViolation(t *testing.T) {
	w := newSCWiring()
	w.repos.commitErr = errors.New("bad object")

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassInvariantViolation)
	if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 0 {
		t.Errorf("%d commit_recorded events for a commit that could not be read", got)
	}
}

// TestASignatureThatCannotBeRecordedIsRefusedRatherThanReported is the B -> C
// window: the commit exists and Rekor holds the entry, but the ledger would
// not take the record. The caller is told, and RM-035's reconciler repairs the
// chain from Rekor (REC-002).
func TestASignatureThatCannotBeRecordedIsRefusedRatherThanReported(t *testing.T) {
	w := newSCWiring()
	w.ledger.failOn[event.EventTypeCommitRecorded] = errors.New("the chain is unreachable")

	_, err := w.call(t, scIn())
	requireClass(t, err, ClassInvariantViolation)

	if got := len(w.ledger.ofType(event.EventTypeCommitIntent)); got != 1 {
		t.Errorf("%d commit_intent events, want 1: the intent is what the reconciler "+
			"matches the Rekor entry to", got)
	}
	if w.signer.calls != 1 {
		t.Errorf("the signer ran %d times, want 1", w.signer.calls)
	}
}

// TestASignerResultThatCannotBeRecordedIsRefusedBeforePhaseC covers the
// members doc 02 §3 requires of `commit_recorded` and the wrapper might not
// have supplied.
func TestASignerResultThatCannotBeRecordedIsRefusedBeforePhaseC(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result signing.Result
	}{
		{"no commit sha", signing.Result{
			Rekor: signing.RekorEntry{UUID: "abc", LogIndex: 1},
		}},
		{"a commit sha that is not an object id", signing.Result{
			CommitSHA: "HEAD",
			Rekor:     signing.RekorEntry{UUID: "abc", LogIndex: 1},
		}},
		{"no rekor uuid", signing.Result{
			CommitSHA: scCommitSHA,
			Rekor:     signing.RekorEntry{LogIndex: 1},
		}},
		{"a negative log index", signing.Result{
			CommitSHA: scCommitSHA,
			Rekor:     signing.RekorEntry{UUID: "abc", LogIndex: -1},
		}},
		{"trailers that are not this run's claim", signing.Result{
			CommitSHA: scCommitSHA,
			Rekor:     signing.RekorEntry{UUID: "abc", LogIndex: 1},
			Trailers: []signing.Trailer{
				{Key: signing.TrailerAgentIdentity, Value: "spiffe://innsegl.dev/agent/demo/rm-033/run-other"},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			result := tc.result
			w.signer.result = &result
			w.repos.commitTree = scTreeHash

			_, err := w.call(t, scIn())
			requireClass(t, err, ClassInvariantViolation)
			if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 0 {
				t.Errorf("%d commit_recorded events for an unusable result", got)
			}
		})
	}
}

// TestAnAppendThatComesBackAsAnotherEventIsRefused.
//
// The ledger returns the ORIGINAL event when an idempotency_key has been used
// before (LED-008). A key that had been spent on something else would hand
// this tool another event's identifiers, so what comes back is checked against
// what was written.
func TestAnAppendThatComesBackAsAnotherEventIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mangle func(event.Fields) event.Fields
	}{
		{"another event type", func(f event.Fields) event.Fields {
			f[event.FieldEventType] = event.EventTypeToolCall
			return f
		}},
		{"another run", func(f event.Fields) event.Fields {
			f[event.FieldRunID] = "run-somebody-else"
			return f
		}},
		{"no event id", func(f event.Fields) event.Fields {
			delete(f, event.FieldEventID)
			return f
		}},
		{"an event id that is not one", func(f event.Fields) event.Fields {
			f[event.FieldEventID] = "not-a-uuid"
			return f
		}},
		{"an event id of the wrong type", func(f event.Fields) event.Fields {
			f[event.FieldEventID] = 42
			return f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			w.ledger.mangle = tc.mangle

			_, err := w.call(t, scIn())
			requireClass(t, err, ClassInvariantViolation)
		})
	}
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

func TestConfigureSignCommitRefusesAnIncompleteConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*SignCommitConfig)
	}{
		{"no run directory", func(c *SignCommitConfig) { c.Runs = nil }},
		{"no ledger", func(c *SignCommitConfig) { c.Ledger = nil }},
		{"no idempotency store", func(c *SignCommitConfig) { c.Idempotency = nil }},
		{"no workspace", func(c *SignCommitConfig) { c.Workspace = nil }},
		{"no sigstore probe", func(c *SignCommitConfig) { c.Sigstore = nil }},
		{"no credentials", func(c *SignCommitConfig) { c.Credentials = nil }},
		{"no signers", func(c *SignCommitConfig) { c.Signers = nil }},
		{"no author name", func(c *SignCommitConfig) { c.AuthorName = "" }},
		{"no author email", func(c *SignCommitConfig) { c.AuthorEmail = "" }},
		// RM-079 (#116), reachable exactly as the nine rows above are:
		// SignCommitConfig and ConfigureSignCommit are exported, so a wiring
		// site can leave this nil, and catching that AT START-UP rather than
		// at an agent's first commit is the whole job of these guards.
		{"no pseudonymiser", func(c *SignCommitConfig) { c.Pseudonyms = nil }},
		{"an author the policy does not admit", func(c *SignCommitConfig) {
			c.Signers = &scSigners{signer: &scSigner{}, admitErr: signing.ErrAuthorNotAdmitted}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			cfg := w.cfg
			tc.edit(&cfg)
			if _, err := newSignCommitService(cfg); err == nil {
				t.Fatal("the configuration was accepted; a missing gate is an open door")
			}
		})
	}

	w := newSCWiring()
	if _, err := newSignCommitService(w.cfg); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
}

// TestReposDefaultsToTheShippedGitReader: Repos is the one dependency with a
// default, because there is exactly one way to read a git index.
func TestReposDefaultsToTheShippedGitReader(t *testing.T) {
	w := newSCWiring()
	w.cfg.Repos = nil
	svc, err := newSignCommitService(w.cfg)
	if err != nil {
		t.Fatalf("newSignCommitService: %v", err)
	}
	if _, ok := svc.repos.(GitRepos); !ok {
		t.Fatalf("Repos defaulted to %T, want GitRepos", svc.repos)
	}
}

func TestSignCommitIsNotServedUntilItIsConfigured(t *testing.T) {
	restore, err := ConfigureSignCommit(newSCWiring().cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	restore()

	_, err = signCommit(t.Context(), nil, scIn())
	requireClass(t, err, ClassInvariantViolation)
}

func TestConfigureSignCommitRefusesTheIncompleteAndRestoresThePrevious(t *testing.T) {
	w := newSCWiring()
	bad := w.cfg
	bad.Signers = nil
	if _, err := ConfigureSignCommit(bad); err == nil {
		t.Fatal("an incomplete configuration was installed")
	}

	restore, err := ConfigureSignCommit(w.cfg)
	if err != nil {
		t.Fatalf("ConfigureSignCommit: %v", err)
	}
	// A malformed request reaches the configured tool and is refused by the
	// request gate, which is proof the installation took effect: an
	// unconfigured tool refuses with a different message entirely.
	in := scIn()
	in.Repo = "innsegl"
	e := requireClassed(t, mustSignCommitFail(t, in), ClassInvariantViolation)
	if strings.Contains(e.Message, "bound but not configured") {
		t.Fatalf("the tool is still unconfigured: %s", e.Message)
	}

	restore()
	e = requireClassed(t, mustSignCommitFail(t, in), ClassInvariantViolation)
	if !strings.Contains(e.Message, "bound but not configured") {
		t.Fatalf("restore did not put the previous configuration back: %s", e.Message)
	}
}

func mustSignCommitFail(t *testing.T, in signCommitIn) error {
	t.Helper()
	_, err := signCommit(t.Context(), nil, in)
	if err == nil {
		t.Fatal("sign_commit succeeded where it had to refuse")
	}
	return err
}

// ---------------------------------------------------------------------------
// The shipped workspace and git reader.
// ---------------------------------------------------------------------------

func TestTheWorkspaceMapsARepoOntoOneDirectoryAndRefusesEscapes(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, "github.com", "innsegl", "innsegl")
	if err := os.MkdirAll(filepath.Join(want, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}

	ws, err := NewWorkspace(root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	got, err := ws.Worktree(t.Context(), scRepo)
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if got != want {
		t.Errorf("Worktree = %q, want %q", got, want)
	}

	for _, bad := range []string{
		"",
		"innsegl",
		"github.com/innsegl/../../etc",
		"github.com/innsegl/absent",
	} {
		if _, err := ws.Worktree(t.Context(), bad); err == nil {
			t.Errorf("Worktree(%q) was accepted", bad)
		}
	}

	if _, err := NewWorkspace(""); err == nil {
		t.Error("NewWorkspace(\"\") was accepted; there would be no root to resolve against")
	}
	if _, err := NewWorkspace("relative/root"); err == nil {
		t.Error("NewWorkspace with a relative root was accepted")
	}
}

func TestTheWorkspaceRefusesADirectoryThatIsNotAGitWorkingTree(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "github.com", "innsegl", "innsegl"), 0o700); err != nil {
		t.Fatal(err)
	}
	ws, err := NewWorkspace(root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	if _, err := ws.Worktree(t.Context(), scRepo); err == nil {
		t.Error("a directory with no .git was accepted as a working tree")
	}
}

// scGitRepo makes a repository with one staged file and returns its path.
func scGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	scGit(t, dir, "init", "-q", "-b", "main")
	scStage(t, dir, "work.txt", "innsegl RM-033\n")
	return dir
}

func scGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, "nonexistent-gitconfig"),
		"GIT_AUTHOR_NAME="+scAuthorName, "GIT_AUTHOR_EMAIL="+scAuthorEmail,
		"GIT_COMMITTER_NAME="+scAuthorName, "GIT_COMMITTER_EMAIL="+scAuthorEmail,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func scStage(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	scGit(t, dir, "add", name)
}

func TestTheGitReaderResolvesTheStagedTreeAndRefusesEverythingElse(t *testing.T) {
	repo := scGitRepo(t)
	repos := GitRepos{}

	// The caller names what it staged; the reader agrees with the index.
	staged := scGit(t, repo, "write-tree")
	tree, err := repos.StagedTree(t.Context(), repo, staged)
	if err != nil {
		t.Fatalf("StagedTree: %v", err)
	}
	if tree != staged {
		t.Fatalf("StagedTree = %q, want the index tree %q", tree, staged)
	}

	// A ref that names another tree is refused: the intent must record the
	// tree that will be committed, not one the caller hoped for.
	scGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	scStage(t, repo, "second.txt", "more\n")
	if _, err := repos.StagedTree(t.Context(), repo, "HEAD"); err == nil {
		t.Error("HEAD was accepted as the staged tree while the index held something else")
	}

	// Nothing staged: git would refuse to make an empty commit, so this is
	// refused before Phase A rather than after it.
	staged = scGit(t, repo, "write-tree")
	scGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "second")
	if _, err := repos.StagedTree(t.Context(), repo, staged); err == nil {
		t.Error("an index identical to HEAD was accepted; that commit cannot exist")
	}

	for _, bad := range []string{"no-such-ref", ""} {
		if _, err := repos.StagedTree(t.Context(), repo, bad); err == nil {
			t.Errorf("StagedTree accepted %q", bad)
		}
	}
	if _, err := repos.StagedTree(t.Context(), t.TempDir(), "HEAD"); err == nil {
		t.Error("StagedTree accepted a directory that is not a repository")
	}
}

func TestTheGitReaderReadsACommitsTree(t *testing.T) {
	repo := scGitRepo(t)
	// An explicitly named binary and, above, the PATH lookup: both halves of
	// GitRepos.GitPath's default.
	if _, err := (GitRepos{GitPath: "git"}).StagedTree(t.Context(), repo, scGit(t, repo, "write-tree")); err != nil {
		t.Fatalf("StagedTree with an explicit git: %v", err)
	}
	scGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	head := scGit(t, repo, "rev-parse", "HEAD")
	want := scGit(t, repo, "rev-parse", "HEAD^{tree}")

	repos := GitRepos{}
	got, err := repos.CommitTree(t.Context(), repo, head)
	if err != nil {
		t.Fatalf("CommitTree: %v", err)
	}
	if got != want {
		t.Errorf("CommitTree = %q, want %q", got, want)
	}
	if _, err := repos.CommitTree(t.Context(), repo, "no-such-commit"); err == nil {
		t.Error("CommitTree accepted a revision that does not exist")
	}
}

// TestAnEmptyRepositoryStagesItsFirstCommit: a repository with no HEAD has no
// tree to compare against, and that is the ordinary first-commit case rather
// than a refusal.
func TestAnEmptyRepositoryStagesItsFirstCommit(t *testing.T) {
	repo := scGitRepo(t)
	staged := scGit(t, repo, "write-tree")
	got, err := GitRepos{}.StagedTree(t.Context(), repo, staged)
	if err != nil {
		t.Fatalf("StagedTree on a repository with no HEAD: %v", err)
	}
	if got != staged {
		t.Errorf("StagedTree = %q, want %q", got, staged)
	}
}

// ---------------------------------------------------------------------------
// The shipped gitsign factory and the get_credential-backed source.
// ---------------------------------------------------------------------------

func TestTheGitsignFactoryCarriesTheAuthorPolicyItWasBuiltWith(t *testing.T) {
	f := NewGitsignSigners(signing.Config{
		FulcioURL: "http://fulcio.invalid",
		RekorURL:  "http://rekor.invalid",
		Issuer:    "http://issuer.invalid",
		Author:    signing.AuthorPolicy{AllowUnlinked: true},
	})
	if err := f.Admits(scAuthorEmail); err != nil {
		t.Errorf("Admits(%q) = %v, want nil", scAuthorEmail, err)
	}
	if err := f.Admits("someone@github.com"); err == nil {
		t.Error("a linkable address was admitted; I6 has no cryptographic backstop")
	}

	// The zero-value policy admits nothing, which is what makes an
	// unconfigured deployment refuse rather than sign (ADR-0028 decision 6).
	zero := NewGitsignSigners(signing.Config{})
	if err := zero.Admits(scAuthorEmail); err == nil {
		t.Error("the zero-value author policy admitted an address")
	}
	if _, err := zero.Open(nil); err == nil {
		t.Error("a signer was opened with no Fulcio and no Rekor")
	}

	// The success branch. The binaries are named explicitly so the case does
	// not depend on a gitsign being installed: NewSigner resolves both with
	// exec.LookPath and performs no network I/O (ADR-0031).
	opened := NewGitsignSigners(signing.Config{
		FulcioURL:   "http://fulcio.invalid",
		RekorURL:    "http://rekor.invalid",
		Issuer:      "http://issuer.invalid",
		GitsignPath: "git",
		GitPath:     "git",
		Author:      signing.AuthorPolicy{AllowUnlinked: true},
	})
	signer, err := opened.Open(&signCommitSource{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := signer.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// ---------------------------------------------------------------------------
// IP §6.6 — the claim, against a real Postgres.
// ---------------------------------------------------------------------------

// TestTheClaimIsWhatStopsASecondCommit.
//
// IP §6.6: "replaying any request after a crash returns the original result,
// never a second identity, second event, or second commit." The store is what
// makes that true, and it is a Postgres table (doc 05 §2), so this case runs
// against a real one: a map would pass every assertion below while proving
// none of them.
func TestTheClaimIsWhatStopsASecondCommit(t *testing.T) {
	requirePG(t)
	idem, _ := newStore(t)

	w := newSCWiring()
	w.cfg.Idempotency = idem
	svc := w.service(t)

	in := scIn()
	first, err := svc.sign(t.Context(), in)
	if err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	second, err := svc.sign(t.Context(), in)
	if err != nil {
		t.Fatalf("the replay was refused: %v", err)
	}

	if first.CommitSHA != second.CommitSHA || first.RekorEntry != second.RekorEntry ||
		!slices.Equal(first.Trailers, second.Trailers) {
		t.Fatalf("the replay returned %+v and the original was %+v", second, first)
	}
	if w.signer.calls != 1 {
		t.Fatalf("the signer ran %d times for two calls with one key; a second commit "+
			"is exactly what IP §6.6 forbids", w.signer.calls)
	}
	if got := len(w.ledger.ofType(event.EventTypeCommitIntent)); got != 1 {
		t.Errorf("%d commit_intent events for one call", got)
	}
	if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 1 {
		t.Errorf("%d commit_recorded events for one call", got)
	}
	if w.creds.calls != 1 {
		t.Errorf("%d credentials were issued for one call", w.creds.calls)
	}

	// The same key naming a different request is DUPLICATE_REQUEST, never the
	// earlier reply: returning it would answer a question nobody asked
	// (ADR-0004, ADR-0017 §3).
	other := in
	other.Message = "fix: something else entirely"
	_, err = svc.sign(t.Context(), other)
	requireClass(t, err, ClassDuplicateRequest)
}

// TestTheTwoPhaseKeysAreDerivedAndCannotCollideWithAnotherToolsKey.
//
// One tool call appends two events and the ledger's idempotency_key is UNIQUE
// across the chain, so the caller's one key cannot be written twice. Both are
// derived, and the derivation is a pure function of the caller's key.
func TestTheTwoPhaseKeysAreDerivedAndCannotCollideWithAnotherToolsKey(t *testing.T) {
	w := newSCWiring()
	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("sign_commit: %v", err)
	}
	intent := w.ledger.only(t, event.EventTypeCommitIntent)
	recorded := w.ledger.only(t, event.EventTypeCommitRecorded)

	intentKey := scMember[string](t, intent, event.FieldIdempotencyKey)
	recordedKey := scMember[string](t, recorded, event.FieldIdempotencyKey)

	if intentKey == recordedKey {
		t.Fatalf("both phases carry the key %q; the ledger's UNIQUE index would have "+
			"made the second append return the first event", intentKey)
	}
	for _, key := range []string{intentKey, recordedKey} {
		if key == scIn().IdempotencyKey {
			t.Errorf("a phase carries the caller's key verbatim (%q); the same key used "+
				"by record_event would hand this tool a tool_call event's identifiers", key)
		}
		if len(key) > event.MaxIdempotencyKeyBytes {
			t.Errorf("derived key %q is %d bytes, over doc 02 §2's limit", key, len(key))
		}
	}

	// Pure function of the caller's key: a replay derives the same two keys, on
	// any replica, after any crash, with nothing shared between them. And a key
	// at the 128-byte limit still derives keys inside it.
	long := strings.Repeat("k", event.MaxIdempotencyKeyBytes)
	for _, prefix := range []string{signCommitIntentKeyPrefix, signCommitRecordedKeyPrefix} {
		a, b := signCommitPhaseKey(prefix, long), signCommitPhaseKey(prefix, long)
		if a != b {
			t.Errorf("the derivation is not a pure function: %q then %q", a, b)
		}
		if len(a) > event.MaxIdempotencyKeyBytes {
			t.Errorf("a 128-byte key derived %d bytes", len(a))
		}
		if a == signCommitPhaseKey(prefix, long+"x") {
			t.Error("two different caller keys derived one phase key")
		}
	}
}

// ---------------------------------------------------------------------------
// SIG-001, the ledger half, against a real Fulcio, Rekor, SPIRE and Postgres.
// ---------------------------------------------------------------------------
//
// IP §2 draws the line in one sentence: "a mocked Fulcio proves nothing about
// I5." Every assertion above runs against fakes and is about ORDER; this one is
// about a commit that exists, signed under a certificate a real CA issued to a
// real JWT-SVID, with a real transparency-log entry — and the two events, in
// one real hash chain, that record it.
//
// The stack is this process's own (RM-065, #81): both compose files pin a
// project name and a container_name per service, so every process that brings
// one up selects the same one. The overlays rename, and nothing else.
//
// The harness is deliberately not internal/signing's, which lives in that
// package's test files and cannot be imported. It reimplements the OIDC
// provider's registration for the same measured reason ADR-0031 records:
// deploy/compose/spire/register.sh hardcodes the shared container name, and
// WITHOUT that entry the provider holds no SVID, GET /keys answers HTTP 500,
// and Fulcio refuses every token with the message an expired one produces.

const (
	scHarnessTrustDomain = "innsegl.dev"
	// The issuer BOTH stacks must agree on (ADR-0029 decision 3).
	scHarnessIssuer         = "http://spire-oidc:8080"
	scHarnessGitsignVersion = "v0.17.1"
	scHarnessAdminSocket    = "/run/spire/admin/api.sock"
)

type scStack struct {
	project     string
	spireFiles  []string
	sigFiles    []string
	env         []string
	fulcioURL   string
	rekorURL    string
	oidcURL     string
	gitsignPath string
}

func (s *scStack) compose(ctx context.Context, files []string, args ...string) (string, error) {
	full := []string{"compose", "-p", s.project}
	for _, f := range files {
		full = append(full, "-f", f)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	cmd.Env = append(os.Environ(), s.env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s",
			strings.Join(full, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (s *scStack) spireServer(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"exec", "-T", "spire-server", "/opt/spire/bin/spire-server"}, args...)
	full = append(full, "-socketPath", scHarnessAdminSocket)
	return s.compose(ctx, s.spireFiles, full...)
}

// scFindGitsign locates the released binary. It never builds one: IP §7 uses
// Sigstore as a released upstream component.
func scFindGitsign(ctx context.Context) (string, error) {
	if p := os.Getenv("INNSEGL_GITSIGN"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("INNSEGL_GITSIGN=%s: %w", p, err)
		}
		return p, nil
	}
	if p, err := exec.LookPath("gitsign"); err == nil {
		return p, nil
	}
	out, err := exec.CommandContext(ctx, "go", "env", "GOPATH").Output()
	if err == nil {
		p := filepath.Join(strings.TrimSpace(string(out)), "bin", "gitsign")
		if _, serr := os.Stat(p); serr == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no gitsign binary; install the pinned release with "+
		"`go install github.com/sigstore/gitsign@%s` or set INNSEGL_GITSIGN",
		scHarnessGitsignVersion)
}

// scSigstoreOverlay finds the per-process Sigstore overlay. ADR-0031 records
// that the file starts beside its only caller and moves to deploy/compose/ the
// moment a second suite needs it, so both places are looked in and neither is
// created here.
func scSigstoreOverlay(root string) (string, error) {
	for _, candidate := range []string{
		filepath.Join(root, "deploy", "compose", "sigstore-testscope.yml"),
		filepath.Join(root, "internal", "signing", "testdata", "sigstore-testscope.yml"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("no sigstore-testscope.yml in deploy/compose/ or internal/signing/testdata/")
}

func scStartStack(ctx context.Context, root string) (*scStack, error) {
	gitsignPath, err := scFindGitsign(ctx)
	if err != nil {
		return nil, err
	}
	overlay, err := scSigstoreOverlay(root)
	if err != nil {
		return nil, err
	}
	ports := make([]string, 3)
	for i := range ports {
		if ports[i], err = freeHostPort(ctx); err != nil {
			return nil, err
		}
	}
	oidcPort, fulcioPort, rekorPort := ports[0], ports[1], ports[2]

	// A project name of this process's own, and distinct from the one
	// TestGetCredentialAgainstRealSPIRE uses: no two stacks in this binary may
	// select the same compose project.
	project := fmt.Sprintf("innsegl-mcpsign-%d", os.Getpid())
	s := &scStack{
		project: project,
		spireFiles: []string{
			filepath.Join(root, "deploy", "compose", "spire.yml"),
			filepath.Join(root, "deploy", "compose", "spire-testscope.yml"),
		},
		sigFiles: []string{filepath.Join(root, "deploy", "compose", "sigstore.yml"), overlay},
		env: []string{
			"INNSEGL_SPIRE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_TEST_STACK=" + project,
			"INNSEGL_SIGSTORE_OIDC_NETWORK=" + project + "-oidc-frontend",
			"INNSEGL_SPIRE_JWT_ISSUER=" + scHarnessIssuer,
			"INNSEGL_SPIRE_OIDC_PORT=" + oidcPort,
			"INNSEGL_FULCIO_PORT=" + fulcioPort,
			"INNSEGL_REKOR_PORT=" + rekorPort,
		},
		fulcioURL:   "http://127.0.0.1:" + fulcioPort,
		rekorURL:    "http://127.0.0.1:" + rekorPort,
		oidcURL:     "http://127.0.0.1:" + oidcPort,
		gitsignPath: gitsignPath,
	}

	if _, err := s.compose(ctx, s.spireFiles, "up", "-d", "--wait",
		"spire-server", "spire-agent", "spire-oidc"); err != nil {
		return s, fmt.Errorf("bringing up the SPIRE stack: %w", err)
	}
	if err := s.registerOIDCProvider(ctx); err != nil {
		return s, fmt.Errorf("registering the OIDC discovery provider: %w", err)
	}
	if _, err := s.compose(ctx, s.sigFiles, "up", "-d"); err != nil {
		return s, fmt.Errorf("bringing up the Sigstore stack: %w", err)
	}
	if err := s.awaitTrustMaterial(ctx); err != nil {
		return s, err
	}
	return s, nil
}

// registerOIDCProvider is deploy/compose/spire/register.sh's five selectors,
// derived from the running container, for a per-process stack. See the note at
// the top of this section for what its absence looks like.
func (s *scStack) registerOIDCProvider(ctx context.Context) error {
	const spiffeID = "spiffe://" + scHarnessTrustDomain + "/innsegl/oidc-discovery-provider"
	container := s.project + "-spire-oidc"

	out, err := s.spireServer(ctx, "agent", "list")
	if err != nil {
		return err
	}
	parent := ""
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "SPIFFE ID"); ok {
			parent = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
			break
		}
	}
	if parent == "" {
		return fmt.Errorf("no attested agent in `agent list`:\n%s", out)
	}

	imageConfigDigest, err := docker(ctx, "inspect", "--format", "{{.Image}}", container)
	if err != nil {
		return err
	}
	imageRef, err := docker(ctx, "inspect", "--format", "{{.Config.Image}}", container)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "innsegl-mcp-oidc-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binary := filepath.Join(dir, "oidc")
	if _, cperr := docker(ctx, "cp",
		container+":/opt/spire/bin/oidc-discovery-provider", binary); cperr != nil {
		return cperr
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)

	if _, err := s.spireServer(ctx, "entry", "create",
		"-parentID", parent,
		"-spiffeID", spiffeID,
		"-selector", "unix:sha256:"+hex.EncodeToString(sum[:]),
		"-selector", "unix:uid:1000",
		"-selector", "docker:image_config_digest:"+imageConfigDigest,
		"-selector", "docker:label:dev.innsegl.component:oidc-discovery-provider",
		"-selector", "docker:image_id:"+imageRef,
		"-x509SVIDTTL", "1800",
		"-jwtSVIDTTL", "300",
	); err != nil {
		return err
	}
	return s.awaitJWKS(ctx)
}

func (s *scStack) awaitJWKS(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		body, err := scGET(ctx, s.oidcURL+"/keys")
		if err == nil && strings.Contains(string(body), "\"keys\"") {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the OIDC discovery provider never served a JWKS: %w", last)
}

// awaitTrustMaterial waits for ADR-0024's definition of "Sigstore is
// reachable": bytes that PARSE, not a status code. It is the harness's own
// probe and not the production one, so a case cannot pass because the thing it
// is testing agrees with itself.
func (s *scStack) awaitTrustMaterial(ctx context.Context) error {
	deadline := time.Now().Add(4 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		last = s.probeTrustMaterial(ctx)
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("Sigstore never served parseable trust material: %w", last)
}

func (s *scStack) probeTrustMaterial(ctx context.Context) error {
	root, err := scGET(ctx, s.fulcioURL+"/api/v1/rootCert")
	if err != nil {
		return fmt.Errorf("fulcio: %w", err)
	}
	block, _ := pem.Decode(root)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("fulcio: /api/v1/rootCert is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("fulcio: /api/v1/rootCert does not parse: %w", err)
	}
	if !cert.IsCA {
		return errors.New("fulcio: /api/v1/rootCert is not a CA certificate")
	}
	key, err := scGET(ctx, s.rekorURL+"/api/v1/log/publicKey")
	if err != nil {
		return fmt.Errorf("rekor: %w", err)
	}
	kb, _ := pem.Decode(key)
	if kb == nil {
		return errors.New("rekor: /api/v1/log/publicKey is not PEM")
	}
	if _, err := x509.ParsePKIXPublicKey(kb.Bytes); err != nil {
		return fmt.Errorf("rekor: /api/v1/log/publicKey does not parse: %w", err)
	}
	return nil
}

func scGET(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	return body, nil
}

func (s *scStack) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	if os.Getenv("INNSEGL_TEST_KEEP_STACK") != "" {
		return
	}
	for _, files := range [][]string{s.sigFiles, s.spireFiles} {
		if _, err := s.compose(ctx, files, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: compose down: %v\n", err)
		}
	}
}

// scStackMinter mints one audience-bound JWT-SVID through the SPIRE server's
// admin socket — ADR-0019's path, the one get_credential uses.
type scStackMinter struct {
	stack *scStack
	ttl   time.Duration
}

func (m scStackMinter) MintJWTSVID(ctx context.Context, spiffeID, audience string) (MintedCredential, error) {
	out, err := m.stack.spireServer(ctx, "jwt", "mint",
		"-spiffeID", spiffeID, "-audience", audience,
		"-ttl", m.ttl.String(), "-output", "json")
	if err != nil {
		return MintedCredential{}, err
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "{") {
			line = strings.TrimSpace(l)
		}
	}
	if line == "" {
		return MintedCredential{}, fmt.Errorf("no JSON in `jwt mint` output: %s", out)
	}
	var got struct {
		SVID struct {
			ExpiresAt string `json:"expires_at"`
			Token     string `json:"token"`
		} `json:"svid"`
	}
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		return MintedCredential{}, fmt.Errorf("decoding `jwt mint` output: %w", err)
	}
	var unix int64
	if _, err := fmt.Sscanf(got.SVID.ExpiresAt, "%d", &unix); err != nil {
		return MintedCredential{}, fmt.Errorf("decoding expires_at %q: %w", got.SVID.ExpiresAt, err)
	}
	return MintedCredential{
		Token: got.SVID.Token, SPIFFEID: spiffeID, Audience: audience,
		ExpiresAt: time.Unix(unix, 0).UTC(),
	}, nil
}

// scChainRuns is the run directory for the integration case.
//
// internal/rundir is the shipped one and cannot be used here: it imports
// internal/mcp, so an in-package test importing it is an import cycle. This
// reads the same value out of the same place — the `run_registered` record the
// chain returned — rather than out of a literal, so the identity the events
// carry is the identity the ledger holds. What a run IS remains rundir's, and
// is asserted there.
type scChainRuns struct{ run CredentialRun }

func (r scChainRuns) CredentialRun(_ context.Context, runID string) (CredentialRun, bool, error) {
	if runID != r.run.RunID {
		return CredentialRun{}, false, nil
	}
	return r.run, true, nil
}

// scLiteral is identity mode `literal`, which is what every fixture in this
// file is written in terms of.
func scLiteral(t *testing.T) *identity.Pseudonymiser {
	t.Helper()
	p, err := identity.New(identity.ModeLiteral, "")
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	return p
}

// scOpenEntries is the SPIRE registration-entry gate. The entry check is
// TC-SPI's and get_credential's own subject and is measured against a real
// SPIRE in TestGetCredentialAgainstRealSPIRE; this case is about the ledger and
// the signature, so it does not re-litigate it.
type scOpenEntries struct{}

func (scOpenEntries) RequireActiveRun(context.Context, spire.RunRef) error { return nil }

// TestSIG001AgainstRealSigstoreAndARealChain is doc 07 SIG-001's ledger half.
//
// One top-level case with the stack's lifetime, because the mcp package already
// has a TestMain (RM-021's Postgres harness) and Go allows one per binary.
//
// than assumed. Splitting it would separate the evidence from what it proves.
//
//nolint:gocyclo // One assertion per fact, and every fact is measured rather
func TestSIG001AgainstRealSigstoreAndARealChain(t *testing.T) {
	requirePG(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if err := dockerUsable(ctx); err != nil {
		t.Skipf("skipping: no docker (%v). SIG-001 proves nothing about I2, I3 or I5 "+
			"against a mock — IP §2, \"a mocked Fulcio proves nothing about I5\".", err)
	}
	stack, err := scStartStack(ctx, credRepoRoot(t))
	if stack != nil {
		t.Cleanup(stack.stop)
	}
	if err != nil {
		t.Skipf("skipping: could not start the SPIRE and Sigstore stacks (%v). "+
			"The two-phase protocol goes unproven against a real signature. "+
			"Start Docker, `go install github.com/sigstore/gitsign@%s`, and re-run.",
			err, scHarnessGitsignVersion)
	}

	// ---- a real chain -----------------------------------------------------
	dsn := freshDSN(t, requirePG(t))
	migrate(t, dsn)
	store, err := ledger.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(store.Close)

	const (
		runID     = "run-sig001"
		agentType = "demo"
		taskRef   = "RM-033"
		taskID    = "rm-033"
	)
	spiffeID := fmt.Sprintf("spiffe://%s/agent/%s/%s/%s", scHarnessTrustDomain, agentType, taskID, runID)
	registered, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeRunRegistered,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: "sig001-register",
		event.FieldAgentType:      agentType,
		event.FieldTaskRef:        taskRef,
	})
	if err != nil {
		t.Fatalf("seed run_registered: %v", err)
	}
	runs := scChainRuns{run: CredentialRun{
		RunID:     runID,
		AgentType: scMember[string](t, registered, event.FieldAgentType),
		TaskID:    strings.ToLower(scMember[string](t, registered, event.FieldTaskRef)),
		SPIFFEID:  scMember[string](t, registered, event.FieldSpiffeID),
	}}

	// ---- the shipped get_credential, on the real SPIRE ---------------------
	if cerr := ConfigureGetCredential(CredentialConfig{
		Runs:    runs,
		Entries: scOpenEntries{},
		Minter:  scStackMinter{stack: stack, ttl: 5 * time.Minute},
		Ledger:  store,
	}); cerr != nil {
		t.Fatalf("ConfigureGetCredential: %v", cerr)
	}

	// ---- a real repository, with one staged file ---------------------------
	root := t.TempDir()
	const repo = "github.com/innsegl/demo"
	worktree := filepath.Join(root, filepath.FromSlash(repo))
	if merr := os.MkdirAll(worktree, 0o700); merr != nil {
		t.Fatal(merr)
	}
	scGit(t, worktree, "init", "-q", "-b", "main")
	scStage(t, worktree, "work.txt", "innsegl RM-033 SIG-001\n")
	staged := scGit(t, worktree, "write-tree")
	commitsBefore := scCommitObjects(t, worktree)

	workspace, err := NewWorkspace(root)
	if err != nil {
		t.Fatalf("NewWorkspace: %v", err)
	}
	sigstore, err := NewSigstoreEndpoints(SigstoreConfig{
		FulcioURL: stack.fulcioURL, RekorURL: stack.rekorURL,
	})
	if err != nil {
		t.Fatalf("NewSigstoreEndpoints: %v", err)
	}
	idem, _ := newStore(t)

	svc, err := newSignCommitService(SignCommitConfig{
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
		// Identity mode `literal`: this case seeds the chain with a literal
		// SPIFFE ID and asserts the literal trailers against it. PRI-004,
		// below, is the same real stack under `pseudonymous`.
		Pseudonyms: scLiteral(t),
	})
	if err != nil {
		t.Fatalf("newSignCommitService: %v", err)
	}

	// ---- the whole protocol, once -----------------------------------------
	out, err := svc.sign(ctx, signCommitIn{
		RunID:          runID,
		Repo:           repo,
		StagedRef:      staged,
		Message:        "feat(sig-001): a commit signed by a real Fulcio and logged to a real Rekor",
		TaskRef:        taskRef,
		IdempotencyKey: "sig001-sign",
	})
	if err != nil {
		t.Fatalf("sign_commit against the real stack: %v", err)
	}

	// ---- the commit really exists, and is really signed --------------------
	head := scGit(t, worktree, "rev-parse", "HEAD")
	if out.CommitSHA != head {
		t.Fatalf("sign_commit returned %s and HEAD is %s", out.CommitSHA, head)
	}
	if got := scCommitObjects(t, worktree); got != commitsBefore+1 {
		t.Fatalf("the repository holds %d commit objects and held %d before; "+
			"exactly one was created", got, commitsBefore)
	}
	object := scGit(t, worktree, "cat-file", "commit", "HEAD")
	if !strings.Contains(object, "gpgsig ") {
		t.Fatalf("commit %s carries no signature:\n%s", head, object)
	}
	for _, want := range []string{
		signing.TrailerAgentIdentity + ": " + spiffeID,
		signing.TrailerAgentRun + ": " + runID,
		signing.TrailerAgentTask + ": " + taskRef,
	} {
		if !strings.Contains(object, want) {
			t.Errorf("commit %s carries no %q trailer:\n%s", head, want, object)
		}
	}
	if strings.Contains(strings.ToLower(object), "co-authored-by") {
		t.Errorf("commit %s carries a co-authorship trailer; I6 admits none:\n%s", head, object)
	}

	// ---- Rekor really holds the entry --------------------------------------
	//
	// Fetched from the log itself, with the harness's own reader. The wrapper
	// agreeing with itself would prove nothing.
	body, err := scGET(ctx, stack.rekorURL+"/api/v1/log/entries/"+out.RekorEntry.UUID)
	if err != nil {
		t.Fatalf("the Rekor entry sign_commit reported does not exist: %v", err)
	}
	var entries map[string]struct {
		LogIndex       int64 `json:"logIndex"`
		IntegratedTime int64 `json:"integratedTime"`
	}
	if jerr := json.Unmarshal(body, &entries); jerr != nil {
		t.Fatalf("decoding the Rekor entry: %v: %s", jerr, body)
	}
	logged, present := entries[out.RekorEntry.UUID]
	if !present {
		t.Fatalf("Rekor returned no entry keyed %s: %s", out.RekorEntry.UUID, body)
	}
	if logged.LogIndex != out.RekorEntry.LogIndex {
		t.Fatalf("Rekor holds entry %s at index %d and sign_commit reported %d",
			out.RekorEntry.UUID, logged.LogIndex, out.RekorEntry.LogIndex)
	}

	// ---- the chain: intent and recorded, in order, linked ------------------
	chain, err := store.EventsForRun(ctx, runID)
	if err != nil {
		t.Fatalf("EventsForRun: %v", err)
	}
	var types []string
	byType := map[string][]event.Fields{}
	for _, rec := range chain {
		et := scMember[string](t, rec, event.FieldEventType)
		types = append(types, et)
		byType[et] = append(byType[et], rec)
	}
	// The whole run, in chain order. credential_issued sits between the
	// registration and the intent because IP §6.1 aborts before Phase A when
	// the credential cannot be had, so the credential is fetched first.
	wantOrder := []string{
		event.EventTypeRunRegistered,
		event.EventTypeCredentialIssued,
		event.EventTypeCommitIntent,
		event.EventTypeCommitRecorded,
	}
	if !slices.Equal(types, wantOrder) {
		t.Fatalf("the chain for %s is %v, want %v", runID, types, wantOrder)
	}
	if len(byType[event.EventTypeCommitIntent]) != 1 || len(byType[event.EventTypeCommitRecorded]) != 1 {
		t.Fatalf("the chain holds %d intents and %d records, want one of each",
			len(byType[event.EventTypeCommitIntent]), len(byType[event.EventTypeCommitRecorded]))
	}
	intent := byType[event.EventTypeCommitIntent][0]
	recorded := byType[event.EventTypeCommitRecorded][0]

	pa := scMember[int64](t, intent, event.FieldChainPosition)
	pc := scMember[int64](t, recorded, event.FieldChainPosition)
	if pa >= pc {
		t.Fatalf("commit_intent is at chain position %d and commit_recorded at %d", pa, pc)
	}

	// Phase A recorded the tree that was actually signed — measured against
	// git, not against the value this tool passed itself.
	tree := scGit(t, worktree, "rev-parse", "HEAD^{tree}")
	if got := intent[event.FieldTreeHash]; got != tree {
		t.Errorf("commit_intent tree_hash is %v and HEAD's tree is %s", got, tree)
	}
	if got := intent[event.FieldRepo]; got != repo {
		t.Errorf("commit_intent repo is %v, want %q", got, repo)
	}

	// The link.
	if got, want := recorded[event.FieldIntentEventID], intent[event.FieldEventID]; got != want {
		t.Fatalf("commit_recorded intent_event_id is %v and the intent's event_id is %v", got, want)
	}
	if got := recorded[event.FieldCommitSHA]; got != head {
		t.Errorf("commit_recorded commit_sha is %v and HEAD is %s", got, head)
	}
	if got := recorded[event.FieldTreeHash]; got != tree {
		t.Errorf("commit_recorded tree_hash is %v, want %s", got, tree)
	}
	if got := recorded[event.FieldRekorEntryUUID]; got != out.RekorEntry.UUID {
		t.Errorf("commit_recorded rekor_entry_uuid is %v, want %s", got, out.RekorEntry.UUID)
	}
	if got := recorded[event.FieldRekorLogIndex]; got != logged.LogIndex {
		t.Errorf("commit_recorded rekor_log_index is %v and Rekor holds %d", got, logged.LogIndex)
	}

	// The ordering, measured ACROSS the two systems rather than inside one.
	//
	// The chain positions above prove the two events are in order; they cannot
	// prove where the signature fell between them, because the chain does not
	// see Rekor. Rekor's own integration time does: the intent was appended no
	// later than the log integrated the signature, and the record no earlier.
	// Both clocks are the host's — two containers on one machine — and the
	// log's timestamp is second-granular, so a tolerance is allowed rather than
	// pretended away. It is a bound on gross reordering, and the exact
	// transcript proof is the unit case above, whose assertion is shown to bite
	// in TestTheOrderAssertionBitesWhenThePhasesAreReversed.
	const scSkew = 5 * time.Second
	integrated := time.Unix(logged.IntegratedTime, 0).UTC()
	intentTS := scEventTime(t, intent)
	recordedTS := scEventTime(t, recorded)
	if intentTS.After(integrated.Add(scSkew)) {
		t.Errorf("commit_intent was appended at %s and Rekor integrated the signature at %s; "+
			"the intent must not follow the signature (IP §6.5)", intentTS, integrated)
	}
	if recordedTS.Before(integrated.Add(-scSkew)) {
		t.Errorf("commit_recorded was appended at %s and Rekor integrated the signature at %s; "+
			"the record must not precede the signature (IP §6.5)", recordedTS, integrated)
	}

	// ---- IP §6.3, on a run's SECOND commit ---------------------------------
	//
	// RM-034 measured (ADR-0032) that a WARM `signing.Signer` skips its
	// trust-material fetch, so a Rekor outage reaches the caller as
	// `ErrSigning` — a generic refusal — rather than as
	// `ErrTransparencyUnavailable`. IP §6.3 requires the two halves to stay
	// distinguishable, so the question is what THIS tool answers on a run's
	// second commit, and it is measured rather than reasoned about.
	//
	// Two things make the answer TRANSPARENCY_UNAVAILABLE here, and this case
	// exercises both: `NewGitsignSigners` opens one Signer per call, so no
	// cache survives a call and the wrapper's own probe always runs; and
	// `sign_commit` asks the configured Sigstore probe before Phase A, which
	// classifies per half. The unit case
	// TestAGitsignRefusalIsAttributedToWhicheverHalfOfSigstoreIsActuallyDown
	// covers the third path, where Rekor dies after both probes and gitsign's
	// generic refusal is re-probed.
	scStage(t, worktree, "second.txt", "a second commit for the same run\n")
	stagedTwo := scGit(t, worktree, "write-tree")
	commitsBeforeTwo := scCommitObjects(t, worktree)

	if _, serr := stack.compose(ctx, stack.sigFiles, "stop", "rekor"); serr != nil {
		t.Fatalf("stopping rekor: %v", serr)
	}

	_, err = svc.sign(ctx, signCommitIn{
		RunID:          runID,
		Repo:           repo,
		StagedRef:      stagedTwo,
		Message:        "feat(sig-003): a second commit, with Rekor stopped",
		TaskRef:        taskRef,
		IdempotencyKey: "sig001-sign-two",
	})
	outage := requireClassed(t, err, ClassTransparencyUnavailable)
	if !outage.Retryable {
		t.Errorf("%s must be retryable (IP §6.3)", outage.Class)
	}
	// IP §6.3: "A signature without a transparency entry is not non-repudiable
	// and must not exist." Asserted against the object database, not HEAD.
	if got := scCommitObjects(t, worktree); got != commitsBeforeTwo {
		t.Errorf("the repository holds %d commit objects and held %d before the refused "+
			"call; with Rekor down there must be no new commit object at all",
			got, commitsBeforeTwo)
	}
	if head2 := scGit(t, worktree, "rev-parse", "HEAD"); head2 != head {
		t.Errorf("HEAD moved to %s with Rekor down", head2)
	}
	t.Logf("a run's SECOND commit with Rekor stopped: %s (retryable=%v)",
		outage.Class, outage.Retryable)

	t.Logf("SIG-001 ledger half: commit %s, tree %s\n  commit_intent   position %d event_id %v\n"+
		"  commit_recorded position %d intent_event_id %v rekor uuid %s index %d",
		head, tree, pa, intent[event.FieldEventID], pc,
		recorded[event.FieldIntentEventID], out.RekorEntry.UUID, out.RekorEntry.LogIndex)
}

// scEventTime reads a record's server-assigned `ts`.
func scEventTime(t *testing.T, rec event.Fields) time.Time {
	t.Helper()
	raw := scMember[string](t, rec, event.FieldTS)
	ts, err := event.ParseTimestamp(raw)
	if err != nil {
		t.Fatalf("the chain returned %q as a ts: %v", raw, err)
	}
	return ts.Time()
}

// scCommitObjects counts commit objects anywhere in the repository, including
// unreferenced ones. IP §6.3's "no new commit object at all" is a claim about
// git plumbing, not about HEAD.
func scCommitObjects(t *testing.T, worktree string) int {
	t.Helper()
	out := scGit(t, worktree, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype)")
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "commit" {
			n++
		}
	}
	return n
}

// TestARecordedReplyThatIsNotASignCommitResultIsRefused.
//
// ADR-0017's store returns the bytes the first completed call produced. If
// those bytes are not this tool's result shape, something has stored a reply
// under a key this tool then claimed — alert-level, never a zero value handed
// back as though a commit had been signed.
func TestARecordedReplyThatIsNotASignCommitResultIsRefused(t *testing.T) {
	requirePG(t)
	idem, _ := newStore(t)

	w := newSCWiring()
	w.cfg.Idempotency = idem
	svc := w.service(t)
	in := scIn()

	// The same fingerprint the tool computes, with a reply that is not a
	// result. A drift in the tool's Params would make this DUPLICATE_REQUEST
	// instead, which fails loudly rather than passing.
	if _, err := idem.Do(t.Context(), Call{
		Tool: string(ToolSignCommit),
		Key:  in.IdempotencyKey,
		Params: map[string]any{
			"run_id": in.RunID, "repo": in.Repo, "staged_ref": in.StagedRef,
			"message": in.Message, "task_ref": in.TaskRef,
		},
	}, func(context.Context) (any, error) { return "not a sign_commit result", nil }); err != nil {
		t.Fatalf("recording the reply: %v", err)
	}

	_, err := svc.sign(t.Context(), in)
	requireClass(t, err, ClassInvariantViolation)
	if w.signer.calls != 0 {
		t.Errorf("the signer ran %d times for a call answered from the store", w.signer.calls)
	}
}

// TestTheShippedCredentialSourceGoesThroughGetCredential.
//
// SignCommitThroughGetCredential is the seam that keeps one audience
// allowlist, one retirement check and one `credential_issued` append in the
// system. Its three outcomes are driven here; the integration case proves the
// token it returns is one Fulcio accepts.
func TestTheShippedCredentialSourceGoesThroughGetCredential(t *testing.T) {
	run := scRun()
	source := SignCommitThroughGetCredential{}

	newLedger := func() *scLedger { return newSCLedger(nil) }
	install := func(t *testing.T, minter CredentialMinter) {
		t.Helper()
		if err := ConfigureGetCredential(CredentialConfig{
			Runs:    scRuns{run: run, found: true},
			Entries: credOpenEntries{},
			Minter:  minter,
			Ledger:  newLedger(),
		}); err != nil {
			t.Fatalf("ConfigureGetCredential: %v", err)
		}
	}

	t.Run("the credential is the run's, for sigstore", func(t *testing.T) {
		expiry := time.Now().Add(5 * time.Minute)
		install(t, scStubMinter{expiry: expiry})
		got, err := source.IssueForSigning(t.Context(), run)
		if err != nil {
			t.Fatalf("IssueForSigning: %v", err)
		}
		if got.SPIFFEID != run.SPIFFEID {
			t.Errorf("credential identity is %q, want the run directory's %q", got.SPIFFEID, run.SPIFFEID)
		}
		if got.Audience != AudienceSigstore {
			t.Errorf("credential audience is %q, want %q", got.Audience, AudienceSigstore)
		}
		if got.Token == "" {
			t.Error("no token")
		}
		if want := event.NewTimestamp(expiry).Time(); !got.ExpiresAt.Equal(want) {
			t.Errorf("credential expiry is %s, want %s", got.ExpiresAt, want)
		}
	})

	t.Run("get_credential's refusal is carried through unchanged", func(t *testing.T) {
		install(t, scStubMinter{err: Errorf(ClassIdentityUnavailable, run.RunID, "spire is gone")})
		_, err := source.IssueForSigning(t.Context(), run)
		requireClass(t, err, ClassIdentityUnavailable)
	})

	t.Run("an expiry that is not a timestamp is an invariant violation", func(t *testing.T) {
		// doc 02 §1's form has a four-digit year, so an instant outside it
		// renders as something ParseTimestamp refuses. A credential whose
		// stated expiry cannot be read is one nothing can refuse when it
		// expires (IP §6.2).
		install(t, scStubMinter{expiry: time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC)})
		_, err := source.IssueForSigning(t.Context(), run)
		requireClass(t, err, ClassInvariantViolation)
	})
}

// credOpenEntries is the SPIRE entry gate, open. get_credential's own tests
// measure it closed.
type credOpenEntries struct{}

func (credOpenEntries) RequireActiveRun(context.Context, spire.RunRef) error { return nil }

// scStubMinter is SPIRE, as get_credential sees it.
type scStubMinter struct {
	expiry time.Time
	err    error
}

func (m scStubMinter) MintJWTSVID(_ context.Context, spiffeID, audience string) (MintedCredential, error) {
	if m.err != nil {
		return MintedCredential{}, m.err
	}
	return MintedCredential{
		Token: "stub.jwt.svid", SPIFFEID: spiffeID, Audience: audience, ExpiresAt: m.expiry,
	}, nil
}

// TestTheGitReaderRefusesAnIndexItCannotResolve.
//
// `staged_ref` resolves against the object database and the index does not, so
// a corrupt index is the one state in which the first read succeeds and the
// second cannot. It is refused before Phase A like every other repository
// failure.
func TestTheGitReaderRefusesAnIndexItCannotResolve(t *testing.T) {
	repo := scGitRepo(t)
	staged := scGit(t, repo, "write-tree")

	// The tree object still exists, so rev-parse answers; the index no longer
	// parses, so write-tree cannot.
	if err := os.WriteFile(filepath.Join(repo, ".git", "index"),
		[]byte("not an index\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (GitRepos{}).StagedTree(t.Context(), repo, staged); err == nil {
		t.Fatal("an index git cannot resolve to a tree was accepted")
	}
}
