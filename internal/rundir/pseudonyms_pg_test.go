// SPDX-License-Identifier: Apache-2.0

package rundir

import (
	"context"
	"errors"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	pseudo "innsegl.dev/innsegl/internal/identity"
)

// MCP-098 (ADR-0080 decision 4): the run directory every tool and the commit
// path read a run through resolves its repository and branch, on a chain
// that switched to pseudonymous mode part-way and rotated its key.
func TestMCP098TheRunDirectoryResolvesRepositoryAndBranch(t *testing.T) {
	store := newLedger(t)
	appendRegistered(t, store, "run-before", "register-run-before")

	for _, key := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		repos, err := pseudo.NewRepositories(pseudo.ModePseudonymous, key)
		if err != nil {
			t.Fatal(err)
		}
		store.UseRepositories(repos)
		runID := "run-" + key[:1]
		rec := appendRegistered(t, store, runID, "register-"+runID)
		if repo, ok := rec[event.FieldRepo].(string); !ok || !event.IsPseudonym(repo) {
			t.Fatalf("the chain holds %v for %s, want a pseudonym", rec[event.FieldRepo], runID)
		}
	}

	d, err := New(Config{Events: store})
	if err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"run-before", "run-a", "run-b"} {
		run, found, err := d.CredentialRun(context.Background(), runID)
		if err != nil || !found {
			t.Fatalf("CredentialRun(%s) = %v, %v", runID, found, err)
		}
		if run.Repo != "github.com/acme/api" || run.Branch != "main" {
			t.Errorf("%s reads as %q on %q, want github.com/acme/api on main", runID, run.Repo, run.Branch)
		}
	}
}

type namingEvents struct {
	fakeEvents
	names map[string]string
	err   error
}

func (n *namingEvents) ResolveNames(_ context.Context, values ...string) (map[string]string, error) {
	if n.err != nil {
		return nil, n.err
	}
	out := map[string]string{}
	for _, v := range values {
		out[v] = v
		if l, ok := n.names[v]; ok {
			out[v] = l
		}
	}
	return out, nil
}

// MCP-098's other paths, without a database: a literal chain is never asked
// to resolve, an erased name reads as itself, and the resolver's own failure
// is carried across rather than read as a name.
func TestMCP098ResolutionPaths(t *testing.T) {
	const pn = "pn:rk-0a1b2c3d:0123456789abcdef0123456789abcdef"
	withRepo := func(repo string) []event.Fields {
		r := registered(1, "2026-10-10T10:00:00.000Z")
		r[event.FieldRepo] = repo
		return []event.Fields{r}
	}

	t.Run("a literal record is read as it is", func(t *testing.T) {
		n := &namingEvents{fakeEvents: fakeEvents{records: withRepo(testRepo)}, err: errResolverDown}
		d, err := New(Config{Events: n})
		if err != nil {
			t.Fatal(err)
		}
		run, found, err := d.CredentialRun(context.Background(), testRunID)
		if err != nil || !found || run.Repo != testRepo {
			t.Errorf("= %q, %v, %v", run.Repo, found, err)
		}
	})
	t.Run("an erased name reads as its pseudonym", func(t *testing.T) {
		n := &namingEvents{fakeEvents: fakeEvents{records: withRepo(pn)}}
		d, err := New(Config{Events: n})
		if err != nil {
			t.Fatal(err)
		}
		run, _, err := d.CredentialRun(context.Background(), testRunID)
		if err != nil || run.Repo != pn {
			t.Errorf("= %q, %v", run.Repo, err)
		}
	})
	t.Run("the resolver's failure is the read's failure", func(t *testing.T) {
		n := &namingEvents{fakeEvents: fakeEvents{records: withRepo(pn)}, err: errResolverDown}
		d, err := New(Config{Events: n})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, cerr := d.CredentialRun(context.Background(), testRunID); !errors.Is(cerr, errResolverDown) {
			t.Errorf("err = %v, want %v", cerr, errResolverDown)
		}
	})
}

var errResolverDown = errorString("the alias table did not answer")

type errorString string

func (e errorString) Error() string { return string(e) }
