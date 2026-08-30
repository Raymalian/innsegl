// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// The refusals and the failure paths.
//
// A repair component's error paths are not incidental: every one of them is a
// place where "we could not tell" could be turned into a permanent record, and
// IP §6.4 requires the ledger's own failures to be reported rather than
// swallowed. Each case below reaches one.

func TestNewRefusesAReconcilerMissingAnyHalf(t *testing.T) {
	full := func() reconciler.Config {
		m := newMemLedger(time.Now)
		return reconciler.Config{
			Ledger: m, Appender: m,
			Repos:       &fakeRepos{},
			Log:         &fakeLog{},
			TrustDomain: testTrustDomain,
		}
	}
	if _, err := reconciler.New(full()); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
	for name, remove := range map[string]func(*reconciler.Config){
		"no ledger":       func(c *reconciler.Config) { c.Ledger = nil },
		"no appender":     func(c *reconciler.Config) { c.Appender = nil },
		"no repositories": func(c *reconciler.Config) { c.Repos = nil },
		"no log":          func(c *reconciler.Config) { c.Log = nil },
		"no trust domain": func(c *reconciler.Config) { c.TrustDomain = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := full()
			remove(&cfg)
			if _, err := reconciler.New(cfg); err == nil {
				t.Fatalf("a reconciler with %s was accepted; that is a repair component "+
					"reporting agreement it never checked", name)
			}
		})
	}
}

func TestALedgerThatRefusesTheRepairFailsTheCycleWithoutLosingTheFinding(t *testing.T) {
	for eventType, prepare := range map[string]func(*fixture){
		event.EventTypeCommitRecorded:      func(f *fixture) { f.signIt(testCommit, testTree, spiffeIDFor(f.runID)) },
		event.EventTypeCommitIntentExpired: func(*fixture) {},
	} {
		t.Run(eventType, func(t *testing.T) {
			f := newFixture(t, "run-refused", testTree)
			prepare(f)
			f.ledger.failOn = eventType
			f.clock.at = f.clock.at.Add(time.Hour)

			result, err := f.reconciler(t, 15*time.Minute).Reconcile(context.Background())
			if err == nil {
				t.Fatal("a ledger that refused the append produced no error")
			}
			if !strings.Contains(err.Error(), "refusing to append") {
				t.Fatalf("the ledger's own words are not carried across: %v", err)
			}
			// The finding survives. A ledger that refused is a reason to fail
			// the cycle, never a reason to go quiet about what it found.
			if len(result.Findings) != 1 {
				t.Fatalf("the cycle reported %d findings, want 1", len(result.Findings))
			}
		})
	}
}

// brokenLedger fails the chain read at a chosen point.
type brokenLedger struct {
	inner    *memLedger
	failIn   string
	failWith error
}

func (b *brokenLedger) Count(ctx context.Context) (int64, error) {
	if b.failIn == "count" {
		return 0, b.failWith
	}
	return b.inner.Count(ctx)
}

func (b *brokenLedger) Events(ctx context.Context, from, to int64) ([]event.Fields, error) {
	if b.failIn == "events" {
		return nil, b.failWith
	}
	return b.inner.Events(ctx, from, to)
}

func TestAChainThatCannotBeReadFailsTheCycle(t *testing.T) {
	for _, failIn := range []string{"count", "events"} {
		t.Run(failIn, func(t *testing.T) {
			f := newFixture(t, "run-unreadable", testTree)
			broken := &brokenLedger{inner: f.ledger, failIn: failIn,
				failWith: errors.New("postgres is down")}
			r, err := reconciler.New(reconciler.Config{
				Ledger: broken, Appender: f.ledger, Repos: f.repos, Log: f.log,
				TrustDomain: testTrustDomain, Now: f.clock.now,
				Alert: func(context.Context, reconciler.Finding) {}, Observe: func(reconciler.Result, error) {},
			})
			if err != nil {
				t.Fatalf("reconciler.New: %v", err)
			}
			if _, rerr := r.Reconcile(context.Background()); rerr == nil {
				t.Fatal("an unreadable chain produced no error")
			}
		})
	}
}

// The chain is read tolerantly: doc 02 §1 says a verifier tolerates an event
// from a newer schema_version, and refusing to reconcile because ONE event was
// unreadable would turn a forward-compatibility case into an outage of the
// repair. Each of these intents is skipped, and the cycle still runs.
func TestAnUnreadableIntentIsSkippedRatherThanFatal(t *testing.T) {
	for name, mangle := range map[string]func(event.Fields){
		"no event_id": func(f event.Fields) { delete(f, event.FieldEventID) },
		"no ts":       func(f event.Fields) { delete(f, event.FieldTS) },
		"a ts that is not a timestamp": func(f event.Fields) {
			f[event.FieldTS] = "the day before yesterday"
		},
		"no repo":      func(f event.Fields) { delete(f, event.FieldRepo) },
		"no tree_hash": func(f event.Fields) { delete(f, event.FieldTreeHash) },
		"no run_id":    func(f event.Fields) { delete(f, event.FieldRunID) },
		"no spiffe_id": func(f event.Fields) { delete(f, event.FieldSpiffeID) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "run-mangled", testTree)
			// The stored record is mutated in place, which no production path
			// can do — the point is what a READER does with a record it cannot
			// make sense of, not how one could come to exist.
			mangle(f.ledger.records[len(f.ledger.records)-1])
			f.clock.at = f.clock.at.Add(time.Hour)

			result := f.reconcile(t, 15*time.Minute)
			if len(result.Appended) != 0 {
				t.Fatalf("an unreadable intent produced appends %v", result.Appended)
			}
			if result.Open != 0 {
				t.Fatalf("an unreadable intent was acted on: %+v", result.Findings)
			}
		})
	}
}

// A `commit_recorded` whose `intent_event_id` cannot be read resolves no
// intent, so the next cycle finds that intent open again — and its append is
// then refused by the key it already spent, LOUDLY. That is the outcome to
// want: the chain and the repair disagree, and the cycle says so instead of
// recording a second attribution or going quiet.
func TestAResolutionThatNamesNoIntentIsReportedRatherThanSilentlyReRepaired(t *testing.T) {
	f := newFixture(t, "run-openagain", testTree)
	f.signIt(testCommit, testTree, spiffeIDFor(f.runID))
	f.clock.at = f.clock.at.Add(time.Hour)
	f.reconcile(t, 15*time.Minute)

	before := len(f.ledger.types())
	delete(f.ledger.records[len(f.ledger.records)-1], event.FieldIntentEventID)

	result, err := f.reconciler(t, 15*time.Minute).Reconcile(context.Background())
	if err == nil {
		t.Fatal("a chain whose repair names no intent produced no error")
	}
	if !strings.Contains(err.Error(), "naming intent") {
		t.Fatalf("the error does not say what came back: %v", err)
	}
	if result.Open != 1 {
		t.Fatalf("Open=%d, want 1 — a record that names no intent resolves none", result.Open)
	}
	if got := len(f.ledger.types()); got != before {
		t.Fatalf("the chain grew from %d to %d; the key it already spent must refuse",
			before, got)
	}
}

// countingAppender records what it was asked to append and answers with
// something else, the way a chain another writer got to first would.
type countingAppender struct {
	mu    sync.Mutex
	reply event.Fields
}

func (c *countingAppender) Append(context.Context, event.Fields) (event.Fields, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reply, nil
}

func TestAnAppendThatComesBackAsAnotherEventIsRefused(t *testing.T) {
	for name, reply := range map[string]event.Fields{
		"another event type": {
			event.FieldEventType: event.EventTypeToolCall,
			event.FieldEventID:   "01a047a7-77c0-7ed1-a1f2-b72f793a5edf",
		},
		"another intent": {
			event.FieldEventType:     event.EventTypeCommitIntentExpired,
			event.FieldEventID:       "01a047a7-77c0-7ed1-a1f2-b72f793a5edf",
			event.FieldIntentEventID: "01a047a7-62f6-7ca8-b29c-ffd68aa542e3",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, "run-wrongreply", testTree)
			f.clock.at = f.clock.at.Add(time.Hour)
			r, err := reconciler.New(reconciler.Config{
				Ledger: f.ledger, Appender: &countingAppender{reply: reply},
				Repos: f.repos, Log: f.log, TrustDomain: testTrustDomain,
				ExpireAfter: 15 * time.Minute, Now: f.clock.now,
				Alert: func(context.Context, reconciler.Finding) {}, Observe: func(reconciler.Result, error) {},
			})
			if err != nil {
				t.Fatalf("reconciler.New: %v", err)
			}
			if _, rerr := r.Reconcile(context.Background()); rerr == nil {
				t.Fatalf("an append that came back as %v was accepted", reply[event.FieldEventType])
			}
		})
	}
}

func TestRunRefusesANonPositiveIntervalAndStopsWithItsContext(t *testing.T) {
	f := newFixture(t, "run-loop", testTree)
	r := f.reconciler(t, 15*time.Minute)

	if err := r.Run(context.Background(), 0); err == nil {
		t.Fatal("a zero interval was accepted; IP §6.5 requires the reconciler to run continuously")
	}

	var (
		mu     sync.Mutex
		cycles int
	)
	observed, err := reconciler.New(reconciler.Config{
		Ledger: f.ledger, Appender: f.ledger, Repos: f.repos, Log: f.log,
		TrustDomain: testTrustDomain, Now: f.clock.now,
		Alert: func(context.Context, reconciler.Finding) {},
		Observe: func(reconciler.Result, error) {
			mu.Lock()
			cycles++
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if rerr := observed.Run(ctx, 10*time.Millisecond); !errors.Is(rerr, context.DeadlineExceeded) {
		t.Fatalf("Run returned %v, want the context's own error", rerr)
	}
	mu.Lock()
	defer mu.Unlock()
	if cycles < 2 {
		t.Fatalf("Run performed %d cycles in 200ms at a 10ms interval", cycles)
	}
}

// The default sinks. A deployment that names none still gets the alert doc 05
// §4 requires, and a cycle that reaches neither branch of the observer is a
// cycle nobody would see.
func TestTheDefaultSinksAreExercisedByEveryCycleShape(t *testing.T) {
	build := func(f *fixture) *reconciler.Reconciler {
		r, err := reconciler.New(reconciler.Config{
			Ledger: f.ledger, Appender: f.ledger, Repos: f.repos, Log: f.log,
			TrustDomain: testTrustDomain, ExpireAfter: 15 * time.Minute, Now: f.clock.now,
		})
		if err != nil {
			t.Fatalf("reconciler.New: %v", err)
		}
		return r
	}

	// Unresolved: the default Alert runs.
	unresolved := newFixture(t, "run-defalert", testTree)
	unresolved.repos.err = errors.New("no working tree")
	unresolved.clock.at = unresolved.clock.at.Add(time.Hour)
	if err := build(unresolved).Run(cancelledAfter(t, 30*time.Millisecond), 10*time.Millisecond); err == nil {
		t.Fatal("Run returned no error on a cancelled context")
	}

	// Acted, then quiet: the default Observe runs both branches.
	acted := newFixture(t, "run-defobserve", testTree)
	acted.signIt(testCommit, testTree, spiffeIDFor(acted.runID))
	acted.clock.at = acted.clock.at.Add(time.Hour)
	if err := build(acted).Run(cancelledAfter(t, 60*time.Millisecond), 10*time.Millisecond); err == nil {
		t.Fatal("Run returned no error on a cancelled context")
	}

	// Failed: the default Observe's error branch.
	broken := newFixture(t, "run-deferr", testTree)
	failing := &brokenLedger{inner: broken.ledger, failIn: "count",
		failWith: errors.New("postgres is down")}
	r, err := reconciler.New(reconciler.Config{
		Ledger: failing, Appender: broken.ledger, Repos: broken.repos, Log: broken.log,
		TrustDomain: testTrustDomain,
	})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	if rerr := r.Run(cancelledAfter(t, 30*time.Millisecond), 10*time.Millisecond); rerr == nil {
		t.Fatal("Run returned no error on a cancelled context")
	}
}

func cancelledAfter(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// ---------------------------------------------------------------------------
// The two readers' own refusals.
// ---------------------------------------------------------------------------

func TestTheWorkspaceReportsItsRoot(t *testing.T) {
	root := t.TempDir()
	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	if ws.Root() == "" || !strings.HasSuffix(ws.Root(), strings.TrimPrefix(root, "/private")) {
		t.Fatalf("Root() = %q, want the configured root %q", ws.Root(), root)
	}
}

func TestTheWorkspaceRefusesARepoThatIsAFile(t *testing.T) {
	root, worktree := newRepo(t, "github.com/innsegl/demo")
	_ = worktree
	if err := writeFileAt(t, root, "github.com/innsegl/file", "x"); err != nil {
		t.Fatal(err)
	}
	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	_, err = ws.SignedCommitsWithTree(context.Background(),
		"github.com/innsegl/file", strings.Repeat("a", 40))
	if err == nil {
		t.Fatal("a regular file was accepted as a working tree")
	}
}

func TestGitFailuresAreErrorsRatherThanEmptyAnswers(t *testing.T) {
	root := t.TempDir()
	// A directory that exists and is not a git repository at all. Every git
	// invocation below fails, and none of them may be read as "no candidates".
	if err := writeDirAt(t, root, "github.com/innsegl/notarepo"); err != nil {
		t.Fatal(err)
	}
	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	if _, serr := ws.SignedCommitsWithTree(context.Background(),
		"github.com/innsegl/notarepo", strings.Repeat("a", 40)); serr == nil {
		t.Fatal("a directory that is not a repository produced no error")
	}
}

func TestTheLogReaderRefusesAnIndexAnswerTooLargeToTrust(t *testing.T) {
	uuids := make([]string, 0, 100)
	for i := range 100 {
		uuids = append(uuids, fmt.Sprintf("%064x", i))
	}
	quoted := make([]string, 0, len(uuids))
	for _, u := range uuids {
		quoted = append(quoted, `"`+u+`"`)
	}
	l := &logServer{indexBody: "[" + strings.Join(quoted, ",") + "]"}
	_, err := l.start(t).EntryForCommit(context.Background(), testCommit)
	if err == nil {
		t.Fatal("an index answer of 100 entries for one artifact hash was walked")
	}
	if errors.Is(err, reconciler.ErrNoEntry) {
		t.Fatalf("an untrustworthy index answer was reported as an absence: %v", err)
	}
}

func TestTheLogReaderQuotesABoundedPartOfARefusal(t *testing.T) {
	l := &logServer{indexStatus: http.StatusBadGateway}
	_, err := l.start(t).EntryForCommit(context.Background(), testCommit)
	if err == nil {
		t.Fatal("a 502 produced no error")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("the status is not in the error: %v", err)
	}
}
