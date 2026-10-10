// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// REC-019 (ADR-0080 decision 4, ADR-0065's amendment): the reconciler reads a
// pseudonymous intent's repository by its resolved name, copies the chain's
// own value onto a repair, and leaves an intent whose name was erased open,
// never expired.

const recPseudonym = "pn:rk-0a1b2c3d:0123456789abcdef0123456789abcdef"

type fakeNames map[string]string

func (n fakeNames) ResolveNames(_ context.Context, values ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range values {
		out[v] = v
		if l, ok := n[v]; ok {
			out[v] = l
		}
	}
	return out, nil
}

type failingNames struct{}

func (failingNames) ResolveNames(context.Context, ...string) (map[string]string, error) {
	return nil, errors.New("the alias table did not answer")
}

// mirrorLike answers a repository only by its literal name; anything else
// is a repository it cannot read, as the mirror cannot read a path for a
// pseudonym.
type mirrorLike struct {
	fakeRepos
	asked []string
}

func (m *mirrorLike) SignedCommitsWithTree(ctx context.Context, repo, tree string) ([]string, error) {
	m.asked = append(m.asked, repo)
	if repo != testRepo {
		return nil, errors.New("no mirror for " + repo)
	}
	return m.fakeRepos.SignedCommitsWithTree(ctx, repo, tree)
}

func pseudonymousFixture(t *testing.T, runID string) (*fixture, *mirrorLike) {
	t.Helper()
	f := newFixture(t, runID, testTree)
	// Re-seed the intent with the chain's pseudonymous value.
	f.ledger = newMemLedger(f.clock.now)
	seedRun(t, f.ledger, runID)
	rec, err := f.ledger.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/intent/" + runID,
		event.FieldRepo:           recPseudonym,
		event.FieldTreeHash:       testTree,
		event.FieldPatchID:        "ffffffffffffffffffffffffffffffffffffffff",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.intent = rec
	m := &mirrorLike{fakeRepos: fakeRepos{commits: map[string]map[string][]string{}}}
	f.repos = &m.fakeRepos
	return f, m
}

func reconcileWith(t *testing.T, f *fixture, repos reconciler.Repos, names reconciler.Names) reconciler.Result {
	t.Helper()
	r, err := reconciler.New(reconciler.Config{
		Ledger: f.ledger, Appender: f.ledger, Repos: repos, Log: f.log, Names: names,
		TrustDomain: testTrustDomain, ExpireAfter: 15 * time.Minute, Now: f.clock.now,
		Alert: func(context.Context, reconciler.Finding) {}, Observe: func(reconciler.Result, error) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestREC019APseudonymousIntentIsReadByItsNameAndRepairedWithTheChainsValue(t *testing.T) {
	f, m := pseudonymousFixture(t, "run-rec019")
	f.signIt(testCommit, testTree, spiffeIDFor(f.runID))
	f.clock.at = f.clock.at.Add(time.Hour)

	res := reconcileWith(t, f, m, fakeNames{recPseudonym: testRepo})
	if res.Repaired != 1 || res.Expired != 0 {
		t.Fatalf("Repaired=%d Expired=%d, want 1 and 0 (asked %v)", res.Repaired, res.Expired, m.asked)
	}
	if len(m.asked) == 0 || m.asked[0] != testRepo {
		t.Errorf("the mirror was asked for %v, want the resolved %s", m.asked, testRepo)
	}
	if got := member[string](t, f.ledger.last(), event.FieldRepo); got != recPseudonym {
		t.Errorf("the repair records repo %q, want the chain's own %q: a name never re-enters the chain", got, recPseudonym)
	}
}

func TestREC019AnErasedNameLeavesTheIntentOpen(t *testing.T) {
	for name, names := range map[string]reconciler.Names{
		"erased":                       fakeNames{},
		"the alias table cannot answer": failingNames{},
	} {
		t.Run(name, func(t *testing.T) {
			f, m := pseudonymousFixture(t, "run-rec019-erased")
			f.clock.at = f.clock.at.Add(time.Hour)
			res := reconcileWith(t, f, m, names)
			if res.Open != 1 || res.Expired != 0 || len(res.Appended) != 0 {
				t.Errorf("Open=%d Expired=%d Appended=%v; want the intent left open and nothing recorded",
					res.Open, res.Expired, res.Appended)
			}
		})
	}
}
