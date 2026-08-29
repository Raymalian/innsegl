// SPDX-License-Identifier: Apache-2.0

package failure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/spire"
)

// TC-SPI, layer F — SPIRE failure injection (RM-018, #26).
//
// doc 07:
//
//	SPI-006 | F | spire-server down at register_agent      | IDENTITY_UNAVAILABLE,
//	                                                         retryable=true, no
//	                                                         queued/provisional
//	                                                         identity anywhere
//	SPI-007 | F | spire-agent socket lost mid-run          | get_credential fails;
//	                                                         in-flight sign_commit
//	                                                         aborts before Phase A
//
// IP §6.1 is the requirement both discharge, and its last sentence is the whole
// of why this file is long:
//
//	"An agent without identity does no attributed work — and the MCP must make
//	 it impossible to do attributed work anonymously, not merely inconvenient."
//
// "Impossible, not inconvenient" is not provable by observing an error return.
// An error return is what a *convenient* refusal looks like too. So every case
// here is built in three parts:
//
//  1. a positive control, showing the same call succeeding against the same
//     stack a moment earlier — without it, "the call failed" is also what a
//     broken harness, a wrong SPIFFE ID or a missing entry looks like;
//  2. a real dependency removed — a SIGKILLed container, waited for, not a stub
//     and not a hopeful sleep — and the attempts counted on the wire, so the
//     refusal cannot be an artefact of a call that never happened;
//  3. an assertion about STATE, not only about the error: what SPIRE holds
//     afterwards, what a workload can fetch afterwards, what the ledger
//     contains afterwards.
//
// Part 3 is the substance. Parts 1 and 2 exist so that part 3 means something.

// testCtx is a context bounded by the case's own patience.
func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// classified extracts the class and retryability an operation must have
// reported. An unclassified error is a failure of the case: IP §4 requires
// every refusal to carry an error_class, and a caller that cannot read one
// cannot fail closed on it.
func classified(t *testing.T, op string, err error) (spire.Class, bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s returned no error", op)
	}
	class, ok := spire.ClassOf(err)
	if !ok {
		t.Fatalf("%s failed with an unclassified error %v (%T); "+
			"the MCP layer has no error_class to report (IP §4)", op, err, err)
	}
	return class, spire.IsRetryable(err)
}

// requireIdentityUnavailable is IP §6.1's refusal, asserted whole: the class,
// and retryable=true. Asserting only that an error came back would pass for
// ATTESTATION_FAILED, which is a different failure with a different meaning to
// the caller — a retryable outage tells a caller to come back, a non-retryable
// attestation failure tells it never to.
func requireIdentityUnavailable(t *testing.T, op string, err error) {
	t.Helper()
	class, retryable := classified(t, op, err)
	if class != spire.ClassIdentityUnavailable {
		t.Fatalf("%s reported %s (%v), want %s (IP §6.1)",
			op, class, err, spire.ClassIdentityUnavailable)
	}
	if !retryable {
		t.Fatalf("%s reported %s as not retryable; IP §6.1 makes an unreachable "+
			"SPIRE the retryable case", op, class)
	}
}

// ---------------------------------------------------------------------------
// SPI-006 — spire-server down at register_agent.
//
// IDENTITY_UNAVAILABLE, retryable=true, and no queued or provisional identity
// anywhere.
//
// The third clause is the one worth writing a test for, and it is the one an
// error assertion cannot reach. "No queued or provisional identity" is a claim
// about what does NOT exist, in a datastore, after the outage is over — so it
// is asserted positively and from four directions:
//
//   - SPIRE's whole entry set, read from the container-private admin socket
//     (unfiltered ground truth), is byte-identical before the kill and after
//     recovery. Anything created under any path, by any name, differs;
//   - it is still identical after a settle window longer than the client's own
//     RPC timeout, so a "register later" that fired on a timer is caught;
//   - a real container carrying the failed run's exact selectors asks the
//     Workload API for that identity and is refused. There is no identity to
//     fetch, provisional or otherwise;
//   - RegisterRun handed back the zero Entry, not a placeholder to be filled
//     in later.
//
// And then the same registration succeeds, which is what makes all four of
// those non-vacuous: the run was registrable the whole time; the only thing
// stopping it was that SPIRE was dead.
// ---------------------------------------------------------------------------

func TestSPI006SpireServerDownAtRegisterAgent(t *testing.T) {
	s := requireStack(t)
	ctx := testCtx(t, 12*time.Minute)

	admin := s.adminClient(t)
	down := newRun(t, "spi006", "rm-018")
	downID, err := down.SPIFFEID(failureTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID for %+v: %v", down, err)
	}

	// -----------------------------------------------------------------------
	// Positive control. Same client, same call, healthy server.
	// -----------------------------------------------------------------------
	control := newRun(t, "spi006-control", "rm-018")
	controlID, err := control.SPIFFEID(failureTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID for %+v: %v", control, err)
	}
	controlEntry := s.registerForTest(t, admin, control)
	if controlEntry.SPIFFEID != controlID {
		t.Fatalf("the control registration created %q, want %q", controlEntry.SPIFFEID, controlID)
	}
	// And the identity is genuinely issuable on this stack, not merely a row:
	// a real workload carrying the control's selectors gets the SVID. Without
	// this, "the failed run has no identity" would also be true of a stack that
	// issues no identities at all.
	issued := s.probeUntilIssued(t, control, 180*time.Second)
	if issued.Outcome.SPIFFEID != controlID {
		t.Fatalf("the control workload was issued %q, want %q", issued.Outcome.SPIFFEID, controlID)
	}
	t.Logf("positive control: %s registered and its SVID issued to a real workload", controlID)

	// The datastore as it stands before anything is killed.
	before, err := s.allEntrySPIFFEIDs(ctx)
	if err != nil {
		t.Fatalf("read the entry set before the kill: %v", err)
	}
	if !slices.Contains(before, controlID) {
		t.Fatalf("the entry set before the kill does not contain the control %q: %v; "+
			"the enumeration is not reading the datastore", controlID, before)
	}
	if slices.Contains(before, downID) {
		t.Fatalf("%q already exists before the case starts: %v", downID, before)
	}
	t.Logf("entry set before the kill: %d entries", len(before))

	// -----------------------------------------------------------------------
	// Inject: SIGKILL spire-server.
	//
	// Deterministic in two steps, because either alone is a race. First the
	// daemon must report the container stopped; then the admin endpoint must
	// stop behaving like a live server — a live SPIRE accepts and waits for a
	// ClientHello, a dead one is refused or closed immediately. Only then is
	// the call under test made. Without the second step the RPC could win the
	// race against the dying process and the test would pass having injected
	// nothing.
	// -----------------------------------------------------------------------
	serverRestored := false
	restoreServer := func() {
		if serverRestored {
			return
		}
		serverRestored = true
		rctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		if err := startContainer(rctx, s.serverContainer, 180*time.Second); err != nil {
			t.Errorf("restarting %s: %v", s.serverContainer, err)
		}
	}
	// Registered before the kill, so a failing assertion cannot leave a dead
	// SPIRE behind for the next case.
	t.Cleanup(restoreServer)

	if err := killContainer(ctx, s.serverContainer); err != nil {
		t.Fatalf("SIGKILL %s: %v", s.serverContainer, err)
	}
	if !waitFor(90*time.Second, func() bool { return adminAPIRefusesConnections(ctx, s.socatAddr) }) {
		t.Fatalf("%s is stopped but the admin endpoint at %s still behaves like a live "+
			"server; the injection did not land and anything below would be vacuous",
			s.serverContainer, s.socatAddr)
	}
	t.Logf("injected: %s SIGKILLed and the admin endpoint confirmed dead", s.serverContainer)

	// -----------------------------------------------------------------------
	// The call under test, with the connections it opens counted.
	// -----------------------------------------------------------------------
	connectionsBefore := s.counter.connections()
	started := time.Now()
	got, registerErr := admin.RegisterRun(ctx, s.registration(down))
	elapsed := time.Since(started)
	attempts := s.counter.connections() - connectionsBefore

	t.Run("the call reached the wire", func(t *testing.T) {
		// The vacuous pass this guards against: an error returned from a
		// client-side check, or from a connection that was never opened,
		// looks identical at the call site to a real refusal from a dead
		// server. Counting accepts on the in-process proxy is the only way to
		// tell the two apart.
		if attempts < 1 {
			t.Fatalf("RegisterRun returned %v after %s having opened %d connections; "+
				"the failure was decided before anything was attempted",
				registerErr, elapsed, attempts)
		}
		t.Logf("RegisterRun opened %d connection(s) in %s before failing", attempts, elapsed.Round(time.Millisecond))
	})

	t.Run("register_agent reports IDENTITY_UNAVAILABLE, retryable", func(t *testing.T) {
		requireIdentityUnavailable(t, "RegisterRun", registerErr)
		var e *spire.Error
		if !errors.As(registerErr, &e) {
			t.Fatalf("RegisterRun returned %T, want *spire.Error", registerErr)
		}
		if e.RunID != down.RunID {
			t.Fatalf("the refusal names run %q, want %q; IP §4's run_id is what a "+
				"caller correlates a retry with", e.RunID, down.RunID)
		}
		t.Logf("verbatim refusal: %v", registerErr)
	})

	t.Run("nothing provisional is handed back to the caller", func(t *testing.T) {
		if !reflect.DeepEqual(got, spire.Entry{}) {
			t.Fatalf("RegisterRun failed and still returned an entry %+v; a caller "+
				"handed a half-built identity has been given something to use", got)
		}
	})

	t.Run("every admin operation is refused the same way while SPIRE is down", func(t *testing.T) {
		// A single refusing entry point is not fail-closed if a neighbouring
		// one answers from a cache. Each of these is asked with SPIRE dead.
		ops := []struct {
			name string
			call func() error
		}{
			{"LookupRun", func() error { _, _, e := admin.LookupRun(ctx, down); return e }},
			{"RequireActiveRun", func() error { return admin.RequireActiveRun(ctx, down) }},
			{"RetireRun", func() error { _, e := admin.RetireRun(ctx, control); return e }},
			{"AttestedNodes", func() error { _, e := admin.AttestedNodes(ctx); return e }},
			{"RegisterRun (control, already created)", func() error {
				_, e := admin.RegisterRun(ctx, s.registration(control))
				return e
			}},
		}
		for _, op := range ops {
			requireIdentityUnavailable(t, op.name, op.call())
		}
		// The last one is the sharpest: SPIRE already holds the control's
		// entry, so a client that answered from anything but the server could
		// have said DUPLICATE_REQUEST and been "right". It has nothing to
		// answer from.
	})

	// -----------------------------------------------------------------------
	// Recovery, and then the part SPI-006 is actually about.
	// -----------------------------------------------------------------------
	restoreServer()
	if !containerHealthy(ctx, s.serverContainer) {
		t.Fatalf("%s did not come back; the assertions below cannot be made", s.serverContainer)
	}
	t.Logf("recovered: %s restarted and healthy", s.serverContainer)

	// A fresh client, so what follows is read from the restarted server's own
	// datastore and not from anything the old connection had cached.
	recovered := s.adminClient(t)

	t.Run("SPIRE holds no entry for the run whose registration failed", func(t *testing.T) {
		entry, found, err := recovered.LookupRun(ctx, down)
		if err != nil {
			t.Fatalf("LookupRun after recovery: %v", err)
		}
		if found {
			t.Fatalf("SPIRE holds %+v for %q: the failed registration was completed "+
				"later. IP §6.1 forbids \"register later\".", entry, downID)
		}
	})

	t.Run("the whole datastore is unchanged, under every path and name", func(t *testing.T) {
		// Not "the run's SPIFFE ID is absent" — that would miss an identity
		// parked under spiffe://innsegl.dev/provisional/... or under a
		// placeholder run id. The entire entry set is compared.
		after, err := s.allEntrySPIFFEIDs(ctx)
		if err != nil {
			t.Fatalf("read the entry set after recovery: %v", err)
		}
		if !slices.Equal(before, after) {
			t.Fatalf("the entry set changed across the outage.\n before: %v\n after:  %v\n"+
				"Something was created while SPIRE was unreachable or on its way back; "+
				"IP §6.1 allows neither.", before, after)
		}
		t.Logf("entry set identical across the outage: %d entries", len(after))
	})

	t.Run("and stays unchanged for longer than anything queued would wait", func(t *testing.T) {
		// The settle window is longer than the client's own RPC timeout (10s,
		// set in adminClient) and longer than spire.DefaultTimeout, so a retry
		// armed by the failed call has had every chance to fire.
		const settle = 30 * time.Second
		deadline := time.Now().Add(settle)
		for time.Now().Before(deadline) {
			after, err := s.allEntrySPIFFEIDs(ctx)
			if err != nil {
				t.Fatalf("read the entry set during the settle window: %v", err)
			}
			if !slices.Equal(before, after) {
				t.Fatalf("an entry appeared %s after recovery without anybody asking for one.\n"+
					" before: %v\n after:  %v\nThat is a queued identity.",
					settle-time.Until(deadline), before, after)
			}
			time.Sleep(2 * time.Second)
		}
		t.Logf("no entry appeared in %s after recovery", settle)
	})

	t.Run("a workload with the run's exact selectors is refused an identity", func(t *testing.T) {
		// The strongest form of the claim. Everything above is about rows in a
		// datastore; this is about whether the failed run can actually do
		// attributed work. The container carries the labels and the uid the
		// registration would have selected on, and asks for its own identity.
		//
		// Asked repeatedly, over a window longer than the agent's cache
		// convergence, and that is not belt-and-braces. A single probe passes
		// spuriously against an entry created moments earlier: RM-014 measured
		// 3–7 seconds for a new entry to reach the agent, so one 0.3s fetch
		// would report "refused" for an identity that was already registered
		// and about to be served. Measured, against a deliberately broken
		// client that completed the registration in the background: the
		// single-probe form of this assertion passed while the datastore
		// assertions above failed. The window is what makes it bite.
		const window = 20 * time.Second
		deadline := time.Now().Add(window)
		attempts := 0
		for time.Now().Before(deadline) {
			refused := s.runProbe(t, down, down)
			attempts++
			if refused.ExitCode == 0 || refused.Outcome.SPIFFEID != "" {
				t.Fatalf("on attempt %d, %s into the window, a workload carrying %+v's "+
					"selectors was issued %q. The run whose registration failed can sign "+
					"as itself: IP §6.1's \"impossible, not merely inconvenient\" is not met.",
					attempts, window-time.Until(deadline), down, refused.Outcome.SPIFFEID)
			}
			if refused.Outcome.Class != spire.ClassAttestationFailed {
				t.Fatalf("on attempt %d the refusal was %s (%q), want %s: SPIRE has no "+
					"entry for this workload, so the Workload API's answer is "+
					"\"no identity issued\"", attempts, refused.Outcome.Class,
					refused.Outcome.Message, spire.ClassAttestationFailed)
			}
			time.Sleep(2 * time.Second)
		}
		if attempts < 4 {
			t.Fatalf("only %d fetches were attempted in %s; too few to outlast the "+
				"agent's entry cache", attempts, window)
		}
		t.Logf("%d workload fetches over %s, every one refused ATTESTATION_FAILED",
			attempts, window)
	})

	t.Run("the same registration succeeds once SPIRE is back", func(t *testing.T) {
		// Without this, every assertion above would also pass for a run that
		// was never registrable — a bad parent, a malformed SPIFFE ID, a
		// selector SPIRE rejects. It was registrable the whole time.
		entry := s.registerForTest(t, recovered, down)
		if entry.SPIFFEID != downID {
			t.Fatalf("the retried registration created %q, want %q", entry.SPIFFEID, downID)
		}
		after, err := s.allEntrySPIFFEIDs(ctx)
		if err != nil {
			t.Fatalf("read the entry set after the retry: %v", err)
		}
		want := append(slices.Clone(before), downID)
		slices.Sort(want)
		if !slices.Equal(want, after) {
			t.Fatalf("after the retry the entry set is\n %v\nwant\n %v\n"+
				"exactly one entry more than before the outage", after, want)
		}
		t.Logf("retry created exactly one entry: %s", downID)
	})
}

// ---------------------------------------------------------------------------
// SPI-006, source half — no queued or provisional identity anywhere.
//
// The behavioural case above proves that none was created during one outage.
// This one asks a different question of the same clause: whether the concept
// exists in the codebase at all. A queue that happened not to fire during a
// 30-second window is still a queue, and IP §6.1 forbids the mechanism, not
// only the observation:
//
//	"No queuing of identity issuance, no provisional identities, no
//	 'register later.'"
//
// Identifiers only, never comments or strings — internal/spire/errors.go
// correctly contains the sentence "it does not get a provisional one", and a
// grep would fail on the documentation of the rule it is checking.
//
// Needs no Docker: it is a property of the source tree.
// ---------------------------------------------------------------------------

// forbiddenIdentityVocabulary is the mechanism IP §6.1 rules out, spelled as
// the names such a mechanism would have. Deliberately narrow: "pendingEntry"
// in a reaper is legitimate, "pendingIdentity" is not.
var forbiddenIdentityVocabulary = regexp.MustCompile(
	`(?i)provisional|(identity|svid|credential)(queue|backlog)|` +
		`(queue|defer)(identity|svid|credential|registration)|registerlater`)

func TestSPI006NoQueuedOrProvisionalIdentityExistsInSource(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var findings []string
	scanned := 0

	for _, tree := range []string{"internal", "cmd"} {
		base := filepath.Join(root, tree)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			scanned++
			ast.Inspect(file, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if forbiddenIdentityVocabulary.MatchString(id.Name) {
					rel, rerr := filepath.Rel(root, path)
					if rerr != nil {
						rel = path
					}
					findings = append(findings,
						fmt.Sprintf("%s:%d: %s", rel, fset.Position(id.Pos()).Line, id.Name))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	if scanned == 0 {
		t.Fatal("no Go files were scanned; this check would pass on an empty repository")
	}
	if len(findings) > 0 {
		t.Fatalf("IP §6.1 forbids queued and provisional identities, and these "+
			"identifiers name one:\n  %s", strings.Join(findings, "\n  "))
	}
	t.Logf("%d Go files under internal/ and cmd/ carry no queued- or "+
		"provisional-identity vocabulary", scanned)
}

// repoRoot is the module root, two directories up from test/failure.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd))
}

// ---------------------------------------------------------------------------
// SPI-007 — spire-agent socket lost mid-run.
//
// get_credential fails, and an in-flight sign_commit aborts before Phase A.
//
// WHAT THIS CASE PROVES, AND WHAT IT DOES NOT
// -------------------------------------------
// PROVED, about shipped code, against a real SPIRE agent that is really killed:
//
//   - a workload that was being issued its SVID a second ago stops being
//     issued one the moment the agent dies. Counted: at least three issuances
//     before the kill, at least three refusals after it, and not one SVID
//     after it — no cache, no last-known-good, no grace path;
//   - every refusal is IDENTITY_UNAVAILABLE with retryable=true, the class
//     IP §6.1 names for a lost socket, produced by internal/spire's own
//     classifier inside the container;
//   - the credential fetch fails by RETURNING AN ERROR — it does not return a
//     degraded credential — so a caller that asks for a credential first has
//     nothing to proceed with;
//   - across that failure the ledger gains no event, and in particular no
//     `commit_intent`. The same writer, in the same shape, demonstrably
//     appends one when the agent is healthy, so its silence is a result and
//     not an absence of plumbing.
//
// NOT PROVED, and it cannot be here: that sign_commit calls get_credential
// before Phase A. sign_commit does not exist yet — it is RM-033 (#41), "the
// two-phase protocol", in E5. What stands in for it below is signCommitPrelude,
// a four-line function in this file that does the two steps whose ORDER IP §6.1
// and §6.5 constrain: get_credential, and only then append `commit_intent`. It
// is a model of the contract, not the implementation of it, and a model cannot
// prove the implementation obeys it.
//
// So SPI-007 is complete only when RM-033 lands. At that point this case must
// be extended to drive the real sign_commit and assert the same two things
// about it: that it fails, and that the ledger holds no `commit_intent` for the
// attempt. Until then it proves the half that is provable — that get_credential
// fails closed — and says so rather than implying the rest.
// ---------------------------------------------------------------------------

// preludeResult is what the stand-in produced.
type preludeResult struct {
	credential spire.FetchOutcome
	// intent is the appended `commit_intent`, or nil when Phase A was never
	// reached because the credential fetch failed first.
	intent event.Fields
}

// signCommitPrelude is NOT sign_commit. See the block comment above.
//
// It is the ordering IP §6.5 requires of Phase A's caller, and nothing else:
// get_credential, and only if that succeeds, append `commit_intent`. Step 1 is
// real — a container carrying the run's selectors calls internal/spire's own
// FetchRunSVID through the Workload API. Step 2 is real — the shipped
// internal/ledger store. Only the ordering between them is this file's.
func (s *stack) signCommitPrelude(t *testing.T, store *ledger.Store, run spire.RunRef, n int) preludeResult {
	t.Helper()

	// Phase 0 — get_credential.
	probe := s.runProbe(t, run, run)
	if probe.ExitCode != 0 || probe.Outcome.SPIFFEID == "" {
		return preludeResult{credential: probe.Outcome}
	}

	// Phase A — the intent, before any signing.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rec, err := store.Append(ctx, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       probe.Outcome.SPIFFEID,
		event.FieldSource:         event.SourceMCP,
		event.FieldIdempotencyKey: fmt.Sprintf("spi007-%s-%d", run.RunID, n),
		event.FieldRepo:           "github.com/raymalian/innsegl",
		event.FieldTreeHash:       strings.Repeat("a1b2", 10),
	})
	if err != nil {
		t.Fatalf("appending commit_intent for %+v: %v", run, err)
	}
	return preludeResult{credential: probe.Outcome, intent: rec}
}

// commitIntentsFor counts the `commit_intent` events the ledger holds for a run.
func commitIntentsFor(t *testing.T, store *ledger.Store, runID string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("ledger.Count: %v", err)
	}
	if count == 0 {
		return 0
	}
	records, err := store.Events(ctx, 1, count)
	if err != nil {
		t.Fatalf("ledger.Events: %v", err)
	}
	n := 0
	for _, rec := range records {
		if rec[event.FieldEventType] == event.EventTypeCommitIntent &&
			rec[event.FieldRunID] == runID {
			n++
		}
	}
	return n
}

func TestSPI007SpireAgentSocketLostMidRun(t *testing.T) {
	s := requireStack(t)
	ctx := testCtx(t, 15*time.Minute)

	admin := s.adminClient(t)
	run := newRun(t, "spi007", "rm-018")
	runID, err := run.SPIFFEID(failureTrustDomain)
	if err != nil {
		t.Fatalf("SPIFFEID for %+v: %v", run, err)
	}
	s.registerForTest(t, admin, run)

	// A real ledger. Skips, loudly, if there is no Postgres — the Phase A half
	// of this case is a claim about a store.
	store := requireLedger(t)

	// -----------------------------------------------------------------------
	// Positive control: the run has a credential, and Phase A is reachable.
	// -----------------------------------------------------------------------
	issued := s.probeUntilIssued(t, run, 180*time.Second)
	if issued.Outcome.SPIFFEID != runID {
		t.Fatalf("the workload was issued %q, want %q", issued.Outcome.SPIFFEID, runID)
	}

	healthy := s.signCommitPrelude(t, store, run, 1)
	if healthy.intent == nil {
		t.Fatalf("with a healthy agent the stand-in never reached Phase A; "+
			"credential outcome was %+v. Everything below would then be vacuous.",
			healthy.credential)
	}
	if n := commitIntentsFor(t, store, run.RunID); n != 1 {
		t.Fatalf("the ledger holds %d commit_intent events for %s after the control, want 1",
			n, run.RunID)
	}
	t.Logf("positive control: credential issued and commit_intent appended at position %v",
		healthy.intent[event.FieldChainPosition])

	// -----------------------------------------------------------------------
	// A run in progress: one container asking for its credential on a timer.
	//
	// "Mid-run" is the point. A single fetch before and a single fetch after
	// would prove the same thing about two different workloads; this is one
	// workload, alive across the failure, and the kill lands only once it has
	// demonstrably been served three times.
	// -----------------------------------------------------------------------
	const iterations = 14
	loop := s.startProbeLoop(t, run, iterations, time.Second, 4*time.Second)
	lastIssued := loop.waitForIssued(t, 3, 180*time.Second)
	t.Logf("the run has been served %d credentials; last at %s", 3, lastIssued.Format(time.RFC3339Nano))

	// The index that separates the two sides of the kill, taken before the
	// kill is initiated. Wall-clock cannot draw this line: the test reads a
	// line some milliseconds after the container wrote it, so a success
	// emitted just before the kill can be *read* just after it and would be
	// indicted as a credential served with no agent. Everything below this
	// index was recorded before the kill was asked for; the single attempt at
	// this index may have been in flight while the container died, and is
	// reported rather than asserted on. Every attempt after it began after the
	// socket was already gone, and those are the ones the case is about.
	inFlightBoundary := loop.count()

	// -----------------------------------------------------------------------
	// Inject: SIGKILL spire-agent. The Workload API socket loses its listener
	// under a running workload.
	// -----------------------------------------------------------------------
	agentRestored := false
	restoreAgent := func() {
		if agentRestored {
			return
		}
		agentRestored = true
		rctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		if err := startContainer(rctx, s.agentContainer, 180*time.Second); err != nil {
			t.Errorf("restarting %s: %v", s.agentContainer, err)
		}
	}
	t.Cleanup(restoreAgent)

	if err := killContainer(ctx, s.agentContainer); err != nil {
		t.Fatalf("SIGKILL %s: %v", s.agentContainer, err)
	}
	killedAt := time.Now()
	t.Logf("injected: %s SIGKILLed at %s", s.agentContainer, killedAt.Format(time.RFC3339Nano))

	loop.wait(t, 5*time.Minute)
	seen, scanErr := loop.seen()
	if scanErr != nil {
		t.Fatalf("%v", scanErr)
	}

	var beforeKill, straddling, afterKill []probeAttempt
	for i, a := range seen {
		switch {
		case i < inFlightBoundary:
			beforeKill = append(beforeKill, a)
		case i == inFlightBoundary && a.At.Sub(killedAt) < 2*time.Second:
			// At most one attempt can straddle the kill: the loop is
			// sequential, so only the fetch that was already running when
			// SIGKILL landed is ambiguous. Bounded to one attempt and to two
			// seconds so it cannot quietly absorb a systematic fail-open.
			straddling = append(straddling, a)
		default:
			afterKill = append(afterKill, a)
		}
	}
	t.Logf("probe loop: %d attempts total, %d before the kill, %d straddling it, %d after",
		len(seen), len(beforeKill), len(straddling), len(afterKill))
	for _, a := range straddling {
		t.Logf("attempt straddling the kill (in flight when SIGKILL landed), not asserted on: %s", a.Raw)
	}

	t.Run("the run really was being issued credentials before the socket was lost", func(t *testing.T) {
		issuedBefore := 0
		for _, a := range beforeKill {
			if a.Outcome.SPIFFEID == "" {
				continue
			}
			issuedBefore++
			if a.Outcome.SPIFFEID != runID {
				t.Fatalf("attempt at %s was issued %q, want %q",
					a.At.Format(time.RFC3339Nano), a.Outcome.SPIFFEID, runID)
			}
		}
		if issuedBefore < 3 {
			t.Fatalf("only %d credentials were issued before the kill; the socket was "+
				"not lost mid-run, it was lost before one started", issuedBefore)
		}
		t.Logf("%d credentials issued to the running workload before the kill", issuedBefore)
	})

	t.Run("every attempt after the kill is refused, and there were several", func(t *testing.T) {
		if len(afterKill) < 3 {
			t.Fatalf("only %d attempts happened after the kill; a refusal nobody asked "+
				"for is not a refusal. Raw attempts: %+v", len(afterKill), seen)
		}
		for _, a := range afterKill {
			if a.Outcome.SPIFFEID != "" {
				t.Fatalf("the workload was issued %q at %s, %s after spire-agent was "+
					"killed. A credential served with no agent is a cached identity, "+
					"and IP §6.1 has no grace path.",
					a.Outcome.SPIFFEID, a.At.Format(time.RFC3339Nano), a.At.Sub(killedAt))
			}
			if a.Outcome.Class != spire.ClassIdentityUnavailable {
				t.Fatalf("attempt at %s reported %s (%q), want %s (IP §6.1: a lost "+
					"spire-agent socket is IDENTITY_UNAVAILABLE)",
					a.At.Format(time.RFC3339Nano), a.Outcome.Class, a.Outcome.Message,
					spire.ClassIdentityUnavailable)
			}
			if !a.Outcome.Retryable {
				t.Fatalf("attempt at %s reported %s as not retryable; a lost socket is "+
					"the retryable case", a.At.Format(time.RFC3339Nano), a.Outcome.Class)
			}
		}
		t.Logf("%d attempts after the kill, all IDENTITY_UNAVAILABLE/retryable; "+
			"first: %q", len(afterKill), afterKill[0].Raw)
	})

	t.Run("get_credential fails for a workload starting now, too", func(t *testing.T) {
		// The loop's container was alive when the agent died. A brand new
		// workload asking for the same identity is refused identically, so the
		// refusal is not an artefact of a broken connection in one process.
		fresh := s.runProbe(t, run, run)
		if fresh.ExitCode == 0 || fresh.Outcome.SPIFFEID != "" {
			t.Fatalf("a fresh workload was issued %q with no spire-agent running",
				fresh.Outcome.SPIFFEID)
		}
		if fresh.Outcome.Class != spire.ClassIdentityUnavailable || !fresh.Outcome.Retryable {
			t.Fatalf("fresh get_credential reported %s retryable=%v (%q), want %s retryable=true",
				fresh.Outcome.Class, fresh.Outcome.Retryable, fresh.Outcome.Message,
				spire.ClassIdentityUnavailable)
		}
	})

	t.Run("the stand-in sign_commit aborts before Phase A", func(t *testing.T) {
		// See the block comment above this case for exactly what this does and
		// does not prove. RM-033 (#41) is where it becomes a statement about
		// sign_commit itself.
		countCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		before, err := store.Count(countCtx)
		if err != nil {
			t.Fatalf("ledger.Count before: %v", err)
		}

		aborted := s.signCommitPrelude(t, store, run, 2)
		if aborted.intent != nil {
			t.Fatalf("the stand-in reached Phase A with no spire-agent running and "+
				"appended %v. IP §6.1: an in-flight sign_commit aborts before Phase A.",
				aborted.intent[event.FieldEventID])
		}
		if aborted.credential.Class != spire.ClassIdentityUnavailable {
			t.Fatalf("it aborted, but on %s (%q); the reason must be the lost socket, "+
				"not something else", aborted.credential.Class, aborted.credential.Message)
		}

		after, err := store.Count(countCtx)
		if err != nil {
			t.Fatalf("ledger.Count after: %v", err)
		}
		if after != before {
			t.Fatalf("the ledger went from %d events to %d across a failed credential "+
				"fetch; nothing may be recorded for work that never got an identity",
				before, after)
		}
		if n := commitIntentsFor(t, store, run.RunID); n != 1 {
			t.Fatalf("the ledger holds %d commit_intent events for %s; only the positive "+
				"control's may exist", n, run.RunID)
		}
		// The chain is intact, so "no new events" is not "the ledger broke".
		records, err := store.Events(countCtx, 1, after)
		if err != nil {
			t.Fatalf("ledger.Events: %v", err)
		}
		if _, err := ledger.Verify(records); err != nil {
			t.Fatalf("the ledger does not verify after the outage: %v", err)
		}
		t.Logf("ledger unchanged at %d events across the failed fetch, chain verifies", after)
	})

	t.Run("the refusal was the injection: credentials resume once the agent is back", func(t *testing.T) {
		restoreAgent()
		back := s.probeUntilIssued(t, run, 240*time.Second)
		if back.Outcome.SPIFFEID != runID {
			t.Fatalf("after the agent restarted the workload was issued %q, want %q",
				back.Outcome.SPIFFEID, runID)
		}
		resumed := s.signCommitPrelude(t, store, run, 3)
		if resumed.intent == nil {
			t.Fatalf("the stand-in still cannot reach Phase A with a healthy agent: %+v",
				resumed.credential)
		}
		if n := commitIntentsFor(t, store, run.RunID); n != 2 {
			t.Fatalf("the ledger holds %d commit_intent events for %s, want 2", n, run.RunID)
		}
	})
}
