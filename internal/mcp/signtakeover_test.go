// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// MCP-011, the window the fuzzer found — RM-169 (#274).
//
// # The shot that fails, and why re-running the campaign hides it
//
// `TestMCP011CrashAndReplayUnderFuzzedKillTiming` kills the server at a drawn
// offset and then replays the same request. One offset — measured at +568.8ms
// in that campaign's blind stratum 2 — lands between the Phase C append and
// the idempotency store's write of the reply. What it leaves behind is not the
// B -> C window IP §6.5 names, even though it looks like it from the
// repository:
//
//	the chain      `commit_intent` AND `commit_recorded`, both for this tree
//	the repository one commit object, HEAD moved to the staged tree
//	the store      a claim, in flight, with no reply and a lease running out
//
// The protocol COMPLETED. Only the answer was lost. But the next caller takes
// the claim over and runs the phases a second time, and the second run reads
// an index the first run's own commit already emptied — so `StagedTree`
// refuses, and the caller is told the repair belongs to the reconciler while
// the record the reconciler would write is already on the chain.
//
// That refusal is what this file pins. The campaign reaches the window only
// when the draw puts it there, so a re-run turns the failure green and the
// window stays open; here it is the fixture rather than the outcome.
//
// # What each case is for
//
//	ATakeoverConvergesOnACommitThatAlreadyLanded
//	    the decision itself, at the level it is made: the phases, given a chain
//	    that already holds this call's `commit_recorded` and an index with
//	    nothing in it.
//	TheTakeoverOfACallKilledBeforeItsReplyWasRecordedConverges
//	    the same window through the real claim: a call interrupted between the
//	    Phase C append and the store's write, its lease run out, and the replay
//	    that takes the claim over.
//	ARefusalStillStandsWhenNothingWasRecorded
//	    the boundary. The convergence must not become a way past the refusal
//	    ADR-0031 decision 6 exists for.
//	ARecordThatCannotBeThisCallsCompletionIsRefused
//	ALedgerThatCannotBeReadIsReportedAsTheOutageItIs
//	ATakeoverWithATaskRefTheGrammarWillNotCarryIsRefused
//	    every error-return path the new question opens, which IP §2's branch
//	    floor requires of every MCP tool.
//
// Nothing here signs a second time, and that is asserted rather than assumed:
// IP §6.6's "never a second commit" is the property the convergence must not
// buy at the cost of.

// scEmptyIndexRefusal is the refusal a takeover actually meets, measured
// rather than spelled out here.
//
// The crashed attempt's own `git commit` moved HEAD to the tree it staged, so
// the index and HEAD now hold the same tree and `git commit` would refuse to
// create a second one. GitRepos.StagedTree says so first. Taking the error
// from the shipped reader — against a real repository in that exact state —
// is what keeps this fixture honest if that message is ever reworded.
func scEmptyIndexRefusal(t *testing.T) error {
	t.Helper()
	repo := scGitRepo(t)
	staged := scGit(t, repo, "write-tree")
	scGit(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "the interrupted attempt's own commit")

	_, err := GitRepos{}.StagedTree(t.Context(), repo, staged)
	if err == nil {
		t.Fatal("an index identical to HEAD was accepted; this fixture is supposed to be the refusal")
	}
	return err
}

// requireSameSignCommitResult asserts two replies of one request are the one
// answer IP §6.6 promises.
func requireSameSignCommitResult(t *testing.T, why string, first, second signCommitOut) {
	t.Helper()
	if first.CommitSHA != second.CommitSHA {
		t.Errorf("%s: the replay names commit %q and the original named %q",
			why, second.CommitSHA, first.CommitSHA)
	}
	if first.RekorEntry.UUID != second.RekorEntry.UUID ||
		first.RekorEntry.LogIndex != second.RekorEntry.LogIndex {
		t.Errorf("%s: the replay names Rekor entry %+v and the original named %+v",
			why, second.RekorEntry, first.RekorEntry)
	}
	if !slices.Equal(first.Trailers, second.Trailers) {
		t.Errorf("%s: the replay carries trailers %v and the original carried %v",
			why, second.Trailers, first.Trailers)
	}
}

// requireOneCommitRecorded asserts the convergence appended nothing: the
// ledger's UNIQUE idempotency_key is what makes that true, and a tool that
// re-derived a different key would break it silently.
func requireOneCommitRecorded(t *testing.T, w *scWiring, signerCalls int) {
	t.Helper()
	if got := len(w.ledger.ofType(event.EventTypeCommitIntent)); got != 1 {
		t.Errorf("the chain holds %d commit_intent events for one call, want exactly 1", got)
	}
	if got := len(w.ledger.ofType(event.EventTypeCommitRecorded)); got != 1 {
		t.Errorf("the chain holds %d commit_recorded events for one call, want exactly 1", got)
	}
	if w.signer.calls != signerCalls {
		t.Errorf("the signer ran %d times, want %d; IP §6.6 forbids a second commit",
			w.signer.calls, signerCalls)
	}
}

// TestMCP011ATakeoverConvergesOnACommitThatAlreadyLanded.
//
// The phases, run a second time over the state the +568.8ms kill leaves: this
// call's `commit_recorded` is on the chain and the index is empty. The second
// run must return the first run's answer rather than refuse it — the commit it
// would be refusing is the one this very call made, and the record that proves
// it is one read away.
func TestMCP011ATakeoverConvergesOnACommitThatAlreadyLanded(t *testing.T) {
	w := newSCWiring()
	in := scIn()

	// The attempt that was killed. All three phases ran; only the reply was
	// lost, which is not something the phases can see.
	first, err := w.call(t, in)
	if err != nil {
		t.Fatalf("the first attempt was refused: %v", err)
	}
	if ordered := requireTwoPhaseOrder(w.phases.all()); ordered != nil {
		t.Fatalf("the interrupted attempt did not run the protocol: %v", ordered)
	}

	// The world it left behind.
	w.repos.stagedErr = scEmptyIndexRefusal(t)

	second, err := w.call(t, in)
	if err != nil {
		t.Fatalf("the takeover was refused, and the commit it refuses is the one this "+
			"call already made and already recorded (RM-169, #274): %v", err)
	}
	requireSameSignCommitResult(t, "the takeover of a call whose commit already landed", first, second)
	requireOneCommitRecorded(t, w, 1)
}

// TestMCP011ARefusalStillStandsWhenNothingWasRecorded.
//
// The convergence must not become a way past the refusal ADR-0031 decision 6
// exists for. A commit object with NO `commit_recorded` is the real B -> C
// window: recovering its Rekor entry is a search internal/signing keeps
// unexported, the repair is RM-035's, and this tool still says so.
func TestMCP011ARefusalStillStandsWhenNothingWasRecorded(t *testing.T) {
	w := newSCWiring()
	w.repos.stagedErr = scEmptyIndexRefusal(t)

	_, err := w.call(t, scIn())
	if err == nil {
		t.Fatal("a takeover with no commit_recorded on the chain was admitted; ADR-0031 " +
			"decision 6 refuses it, because repairing it needs the Rekor search this tool does not have")
	}
	refusal := requireClassed(t, err, ClassInvariantViolation)
	if refusal.Retryable {
		t.Error("the B -> C refusal is retryable; a caller told to retry would re-run Phase B")
	}
	if got := len(w.ledger.ofType(event.EventTypeCommitIntent)); got != 0 {
		t.Errorf("%d commit_intent events were appended by a call refused before Phase A", got)
	}
	if w.signer.calls != 0 {
		t.Errorf("the signer ran %d times for a refused takeover", w.signer.calls)
	}
}

// TestMCP011ARecordThatCannotBeThisCallsCompletionIsRefused.
//
// The convergence reads a reply out of a record and hands it back unchecked to
// a caller that has no way to check it, so every member it reads is one it
// first insists on. A derived key that named another record, a record of
// another run or another repository, a member the schema requires and this one
// does not carry: each is INVARIANT_VIOLATION, because a takeover that answered
// from any of them would attribute somebody else's commit to this run.
//
// The states are written onto the chain rather than appended, because appending
// them is exactly what the ledger refuses — see scLedger.rewriteStored.
func TestMCP011ARecordThatCannotBeThisCallsCompletionIsRefused(t *testing.T) {
	recordedKey := signCommitPhaseKey(signCommitRecordedKeyPrefix, scIn().IdempotencyKey)

	for _, tc := range []struct {
		name string
		edit func(event.Fields)
	}{
		{"the key names another kind of event", func(f event.Fields) {
			f[event.FieldEventType] = event.EventTypeToolCall
		}},
		{"the event type is not even a string", func(f event.Fields) {
			f[event.FieldEventType] = 7
		}},
		{"it is another run's commit", func(f event.Fields) {
			f[event.FieldRunID] = "run-somebody-else"
		}},
		{"it names no run", func(f event.Fields) {
			delete(f, event.FieldRunID)
		}},
		{"it is another repository's commit", func(f event.Fields) {
			f[event.FieldRepo] = "github.com/innsegl/elsewhere"
		}},
		{"it names no repository", func(f event.Fields) {
			delete(f, event.FieldRepo)
		}},
		{"it names no commit", func(f event.Fields) {
			delete(f, event.FieldCommitSHA)
		}},
		{"its commit is not a git object id", func(f event.Fields) {
			f[event.FieldCommitSHA] = "sha256:not-an-object-id"
		}},
		{"it names no Rekor entry", func(f event.Fields) {
			delete(f, event.FieldRekorEntryUUID)
		}},
		{"its Rekor entry is empty", func(f event.Fields) {
			f[event.FieldRekorEntryUUID] = ""
		}},
		{"its log index is not an integer", func(f event.Fields) {
			f[event.FieldRekorLogIndex] = "148203377"
		}},
		{"it names no identity", func(f event.Fields) {
			delete(f, event.FieldSpiffeID)
		}},
		{"its identity is empty", func(f event.Fields) {
			f[event.FieldSpiffeID] = ""
		}},
		// Well formed, and of another task. The trailers are re-derived from
		// the identity the record names and the task_ref the call carries, and
		// `Agent-Task` must lowercase to the identity's {task_id} segment
		// (ADR-0018 §6) — so a record naming another task is a claim this call
		// cannot make, exactly as it would be in Phase B.
		{"its identity is another task's", func(f event.Fields) {
			f[event.FieldSpiffeID] = "spiffe://" + scTrustDomain + "/agent/" +
				scAgentType + "/other-task/" + scRunID
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSCWiring()
			if _, err := w.call(t, scIn()); err != nil {
				t.Fatalf("the first attempt was refused: %v", err)
			}
			w.ledger.rewriteStored(t, recordedKey, tc.edit)
			w.repos.stagedErr = scEmptyIndexRefusal(t)

			_, err := w.call(t, scIn())
			if err == nil {
				t.Fatal("the takeover converged on a record that cannot be this call's completion")
			}
			refusal := requireClassed(t, err, ClassInvariantViolation)
			if refusal.Retryable {
				t.Errorf("the refusal is retryable; the record does not change on a retry: %v", err)
			}
			if w.signer.calls != 1 {
				t.Errorf("the signer ran %d times, want 1; a refused takeover signs nothing",
					w.signer.calls)
			}
		})
	}
}

// TestMCP011ALedgerThatCannotBeReadIsReportedAsTheOutageItIs.
//
// The convergence asks the ledger a question before Phase A, so a ledger that
// cannot answer must be LEDGER_UNAVAILABLE and retryable — the same class the
// appends on either side of it report, and not the alert-level one a refusal
// carries. A takeover told "invariant violation" when the database is merely
// down is an operator paged for an outage that pages itself.
func TestMCP011ALedgerThatCannotBeReadIsReportedAsTheOutageItIs(t *testing.T) {
	w := newSCWiring()
	// The shipped store's own answer to an unreachable database, not a bare
	// error: the class the caller is given is read off this, and a fake that
	// returned something simpler would be testing the fake.
	w.ledger.readErr = &ledger.StoreError{
		Class: ledger.ClassLedgerUnavailable, Op: "event", Retryable: true,
		Err: errors.New("connection refused"),
	}

	_, err := w.call(t, scIn())
	if err == nil {
		t.Fatal("a sign_commit ran with a ledger that cannot be read")
	}
	refusal := requireClassed(t, err, ClassLedgerUnavailable)
	if !refusal.Retryable {
		t.Error("a ledger outage is not retryable; the caller has nothing to do with that")
	}
	if steps := w.phases.all(); len(steps) != 0 {
		t.Errorf("the refused call ran %v; the question is asked before any of them", steps)
	}
}

// TestMCP011ATakeoverWithATaskRefTheGrammarWillNotCarryIsRefused.
//
// The trailers of a converged reply are re-derived rather than remembered, so
// the one argument that derivation depends on is checked here too. ADR-0017's
// store refuses this one layer up — task_ref is in the request digest, so a
// replay that changed it is DUPLICATE_REQUEST and never reaches the phases —
// and the refusal is still this function's to make, because a tool that
// depended on a check another layer happens to perform is a tool whose safety
// moves when that layer does.
func TestMCP011ATakeoverWithATaskRefTheGrammarWillNotCarryIsRefused(t *testing.T) {
	w := newSCWiring()
	if _, err := w.call(t, scIn()); err != nil {
		t.Fatalf("the first attempt was refused: %v", err)
	}
	w.repos.stagedErr = scEmptyIndexRefusal(t)

	replay := scIn()
	replay.TaskRef = "JIRA/118"
	_, err := w.call(t, replay)
	if err == nil {
		t.Fatal("the takeover rendered a trailer from a task_ref the SPIFFE ID grammar cannot carry")
	}
	if refusal := requireClassed(t, err, ClassInvariantViolation); refusal.Retryable {
		t.Errorf("the refusal is retryable; a malformed argument does not become well formed: %v", err)
	}
}

// TestMCP011TheTakeoverOfACallKilledBeforeItsReplyWasRecordedConverges.
//
// The same window, through the claim rather than around it: a real
// IdempotencyStore, a call interrupted between the Phase C append and the
// store's write of the reply, and the replay that takes the claim over once
// the lease runs out.
//
// Cancelling the call's own context at the instant `commit_recorded` becomes
// durable is what the SIGKILL looks like from inside the process: the append
// committed, and nothing the process was going to do next reaches Postgres.
// The claim is therefore left in flight with no reply — exactly the row the
// campaign reads back — and it is the LEASE, not a release, that hands the
// key to the next caller.
func TestMCP011TheTakeoverOfACallKilledBeforeItsReplyWasRecordedConverges(t *testing.T) {
	requirePG(t)
	const lease = 250 * time.Millisecond
	idem, _ := newStore(t, WithIdempotencyLease(lease))

	w := newSCWiring()
	w.cfg.Idempotency = idem
	svc := w.service(t)
	in := scIn()

	killed, kill := context.WithCancel(context.Background())
	defer kill()
	emptied := scEmptyIndexRefusal(t)
	w.ledger.afterAppend = func(eventType string) {
		if eventType != event.EventTypeCommitRecorded {
			return
		}
		kill()
		// The commit the interrupted attempt made is what empties the index,
		// and it is already made by the time Phase C appends.
		w.repos.stagedErr = emptied
	}

	if _, err := svc.sign(killed, in); err == nil {
		t.Fatal("the interrupted call reported success; this case needs its reply to be lost")
	}
	w.ledger.afterAppend = nil

	rec, found, err := idem.Lookup(context.Background(), in.IdempotencyKey)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !found || rec.Status != "in_progress" || len(rec.Response) != 0 {
		t.Fatalf("the interrupted call left record %+v (found %v); this case needs a claim "+
			"still in flight with no reply", rec, found)
	}
	recorded := w.ledger.only(t, event.EventTypeCommitRecorded)

	// The lease is what the campaign waits out too: a takeover is a claim
	// whose holder is presumed gone, not a second concurrent caller.
	time.Sleep(lease + 100*time.Millisecond)

	out, err := svc.sign(context.Background(), in)
	if err != nil {
		t.Fatalf("the takeover of a call whose commit_recorded is already on the chain was "+
			"refused (RM-169, #274): %v", err)
	}
	if want := scMember[string](t, recorded, event.FieldCommitSHA); out.CommitSHA != want {
		t.Errorf("the takeover returned commit %q and the chain records %q", out.CommitSHA, want)
	}
	if want := scMember[string](t, recorded, event.FieldRekorEntryUUID); out.RekorEntry.UUID != want {
		t.Errorf("the takeover returned Rekor entry %q and the chain records %q",
			out.RekorEntry.UUID, want)
	}
	if want := scMember[int64](t, recorded, event.FieldRekorLogIndex); out.RekorEntry.LogIndex != want {
		t.Errorf("the takeover returned log index %d and the chain records %d",
			out.RekorEntry.LogIndex, want)
	}
	requireOneCommitRecorded(t, w, 1)

	// And the answer is now the recorded one, so every further replay is the
	// ordinary ADR-0017 path rather than another takeover.
	again, err := svc.sign(context.Background(), in)
	if err != nil {
		t.Fatalf("replaying after the takeover: %v", err)
	}
	requireSameSignCommitResult(t, "two replays after the takeover", out, again)
	requireOneCommitRecorded(t, w, 1)
}
