// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// Reads scoped to the viewer's organisations (RM-307, #486; plan, Tenancy
// and Hosted core checks).
//
// A run belongs to the organisation of the machine the gateway mapped it
// from: innsegl.gateway_run_mapping.client_id, joined at read time. No event
// field says so, and none has to (doc 02 is untouched). A run no machine is
// mapped to is unowned: runs from before machines enrolled, and runs the core
// itself started. The operator's own organisation sees those, unless the
// deployment hides them (ServerConfig.UnownedRunsHidden).
//
// ONE PLACE DECIDES. ServeHTTP works out the viewer's scope once per request
// and puts it in the request's context; every Store read applies the scope it
// finds there, in SQL, so a count, a page bound and a total never include a
// run the reader may not see. A route added later is scoped without anyone
// remembering to scope it. A run out of scope answers exactly as a run that
// does not exist (gateRun), so a 404 is no oracle for another organisation's
// run ids.
//
// A Store read with no scope in its context reads every run: the commands on
// the core host, and this package's own tests, read the whole ledger.

// OrganisationCookie names the organisation the dashboard's switcher chose.
// Not HttpOnly: the switcher writes it. It only ever narrows the scope; a
// value naming an organisation the viewer is not a member of is ignored.
const OrganisationCookie = "innsegl_organisation"

// RunScope is which runs a reader may see: the runs mapped from these
// machines, and, when Unowned, the runs no machine is mapped to.
type RunScope struct {
	Machines []string
	Unowned  bool
}

type runScopeKey struct{}

// WithRunScope narrows every Store read made with ctx to scope.
func WithRunScope(ctx context.Context, scope RunScope) context.Context {
	return context.WithValue(ctx, runScopeKey{}, scope)
}

// scopeArgs is the scope as two SQL parameters: the machine ids, NULL for
// every run, and whether unowned runs are in.
func scopeArgs(ctx context.Context) (machines []string, unowned bool) {
	scope, ok := ctx.Value(runScopeKey{}).(RunScope)
	if !ok {
		return nil, true
	}
	return nonNilIDs(scope.Machines), scope.Unowned
}

// scopeSQL is the predicate "the run col names is in scope", over parameters
// $m (text[], NULL for every run) and $u (bool). Both subqueries are
// uncorrelated, so each is computed once and hashed rather than run per row.
// A NULL col (an alert about no run) counts as unowned.
func scopeSQL(col string, m, u int) string {
	return fmt.Sprintf(`($%[2]d::text[] IS NULL
	    OR %[1]s IN (SELECT run_id FROM innsegl.gateway_run_mapping WHERE client_id = ANY($%[2]d::text[]))
	    OR ($%[3]d::bool AND (%[1]s IS NULL
	        OR %[1]s NOT IN (SELECT run_id FROM innsegl.gateway_run_mapping WHERE client_id IS NOT NULL))))`,
		col, m, u)
}

// runScopeFor is the viewer's scope: the machines of their live
// memberships (or of the one the switcher chose, when it is theirs), and
// unowned runs when one of those is the operator's organisation. With no
// accounts store there is one tenant and every run is in scope.
func (s *Server) runScopeFor(r *http.Request, userID string) (RunScope, bool, error) {
	if s.orgs == nil {
		return RunScope{}, false, nil
	}
	ctx := r.Context()
	ms, err := s.orgs.Memberships(ctx, userID)
	if err != nil {
		return RunScope{}, true, err
	}
	chosen := ""
	if c, cerr := r.Cookie(OrganisationCookie); cerr == nil {
		for _, m := range ms {
			if m.AccountID == c.Value {
				chosen = c.Value
			}
		}
	}
	var scope RunScope
	ids := []string{}
	for _, m := range ms {
		if chosen != "" && m.AccountID != chosen {
			continue
		}
		ids = append(ids, m.AccountID)
		if m.Operator && !s.unownedRunsHidden {
			scope.Unowned = true
		}
	}
	scope.Machines = []string{}
	if len(ids) > 0 {
		machines, merr := s.orgs.Machines(ctx, ids)
		if merr != nil {
			return RunScope{}, true, merr
		}
		for _, m := range machines {
			scope.Machines = append(scope.Machines, m.ID)
		}
	}
	return scope, true, nil
}

// runRoutePrefix is every route that names one run in its path.
const runRoutePrefix = "/api/v1/runs/"

// gateRun answers a route under /runs/{run_id} with the unknown-run 404 when
// the run is out of scope or does not exist, and reports whether it did. The
// body is Store.Run's own for an unknown run, word for word, so the two
// cannot be told apart. A malformed id is left to the route's own 400: it
// names no run, in scope or out.
func (s *Server) gateRun(w http.ResponseWriter, r *http.Request) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, runRoutePrefix)
	if !ok {
		return false
	}
	runID, _, _ := strings.Cut(rest, "/")
	if event.ValidateIdentifier(runID) != nil {
		return false
	}
	visible, err := s.store.RunVisible(r.Context(), runID)
	if err != nil {
		writeProblem(w, err)
		return true
	}
	if !visible {
		writeProblem(w, unknownRun(runID))
		return true
	}
	return false
}

// unknownRun is the one error for a run this reader cannot see.
func unknownRun(runID string) error {
	return fmt.Errorf("%w: no run %q in this ledger", ErrNotFound, runID)
}

var runVisibleSQL = `
SELECT EXISTS (SELECT 1 FROM innsegl.events
                WHERE run_id = $1 AND event_type = 'run_registered')
       AND ` + scopeSQL("$1::text", 2, 3)

// RunVisible answers whether runID names a registered run in ctx's scope.
func (s *Store) RunVisible(ctx context.Context, runID string) (bool, error) {
	machines, unowned := scopeArgs(ctx)
	var ok bool
	if err := s.pool.QueryRow(ctx, runVisibleSQL, runID, machines, unowned).Scan(&ok); err != nil {
		return false, fmt.Errorf("api: reading whether run %s is in scope: %w", runID, err)
	}
	return ok, nil
}

// visibleRuns answers which of ids are in ctx's scope.
func (s *Store) visibleRuns(ctx context.Context, ids []string) (map[string]bool, error) {
	machines, unowned := scopeArgs(ctx)
	rows, err := s.pool.Query(ctx, `SELECT id FROM unnest($1::text[]) AS id WHERE `+scopeSQL("id", 2, 3),
		nonNilIDs(ids), machines, unowned)
	if err != nil {
		return nil, fmt.Errorf("api: reading which runs are in scope: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("api: reading which runs are in scope: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// hideRelativesOutOfScope blanks every run id among ids that is out of
// ctx's scope: a parent or fork named on a run the reader may see, which
// must not name a run they may not.
func (s *Store) hideRelativesOutOfScope(ctx context.Context, ids ...*string) error {
	var named []string
	for _, id := range ids {
		if *id != "" {
			named = append(named, *id)
		}
	}
	if len(named) == 0 {
		return nil
	}
	visible, err := s.visibleRuns(ctx, named)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if *id != "" && !visible[*id] {
			*id = ""
		}
	}
	return nil
}

// familyInScope keeps runID and the members of its family in ctx's scope.
// A kept member whose parent is dropped reads as having none.
func (s *Store) familyInScope(ctx context.Context, runID string, family []familyNode) ([]familyNode, error) {
	ids := make([]string, len(family))
	for i, n := range family {
		ids[i] = n.RunID
	}
	visible, err := s.visibleRuns(ctx, ids)
	if err != nil {
		return nil, err
	}
	visible[runID] = true
	out := family[:0:0]
	for _, n := range family {
		if !visible[n.RunID] {
			continue
		}
		if n.ParentRunID != "" && !visible[n.ParentRunID] {
			n.ParentRunID = ""
		}
		out = append(out, n)
	}
	return out, nil
}

// eventsInScope answers, of eventIDs, the events in ctx's scope and whether
// each is an alert.
func (s *Store) eventsInScope(ctx context.Context, eventIDs []string) (map[string]bool, error) {
	machines, unowned := scopeArgs(ctx)
	rows, err := s.pool.Query(ctx, `
		SELECT event_id::text,
		       event_type IN ('unattributed_signature_detected', 'ledger_drift_detected')
		  FROM innsegl.events
		 WHERE event_id::text = ANY($1) AND `+scopeSQL("run_id", 2, 3),
		nonNilIDs(eventIDs), machines, unowned)
	if err != nil {
		return nil, fmt.Errorf("api: reading which events are in scope: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		var alert bool
		if err := rows.Scan(&id, &alert); err != nil {
			return nil, fmt.Errorf("api: reading which events are in scope: %w", err)
		}
		out[id] = alert
	}
	return out, rows.Err()
}
