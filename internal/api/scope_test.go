// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// RM-307 (#486; plan, Tenancy and Hosted core checks): the dashboard's reads
// are scoped to the viewer's organisations. A run belongs to the
// organisation of the machine the gateway mapped it from
// (gateway_run_mapping.client_id); a run no machine is mapped to is unowned,
// and only the operator's own organisation sees those. A run out of scope
// answers exactly as a run that does not exist.
//
// The fixture (newOrgHarness, seed 4): organisation A is the operator's,
// B a team the viewer is a member of, C someone else's.
//
//	run-000  laptop, A     repo one
//	run-001  runner, B     repo two, 1 commit
//	run-002  other, C      repo one, 2 commits
//	run-003  unowned       repo two

func newScopeHarness(t *testing.T, opts ...func(*ServerConfig)) orgHarness {
	t.Helper()
	h := newOrgHarness(t, roleOwner, true, opts...)
	insertMapping(t, h.ownerDSN, "run-000", machineLaptop)
	insertMapping(t, h.ownerDSN, "run-001", machineRunner)
	insertMapping(t, h.ownerDSN, "run-002", machineOther)
	return h
}

// as makes the signed-in user a member of exactly these organisations.
func (h orgHarness) as(ms ...OrgMembership) {
	h.orgs.mu.Lock()
	defer h.orgs.mu.Unlock()
	h.orgs.memberships[h.userID] = ms
}

var (
	inA = OrgMembership{AccountID: orgA, Name: "example-org", Operator: true, Role: roleOwner}
	inB = OrgMembership{AccountID: orgB, Name: "example-team", Role: roleMember}
	inC = OrgMembership{AccountID: orgC, Name: "someone-else", Role: roleOwner}
)

func (h orgHarness) runIDs(t *testing.T, cookies ...*http.Cookie) []string {
	t.Helper()
	a := get(t, h.srv.URL, "/api/v1/runs", append([]*http.Cookie{h.cookie}, cookies...)...)
	if a.status != http.StatusOK {
		t.Fatalf("GET /runs = %d: %s", a.status, a.body)
	}
	var page RunPage
	decodeBody(t, a, &page)
	ids := make([]string, 0, len(page.Runs))
	for _, r := range page.Runs {
		ids = append(ids, r.RunID)
	}
	slices.Sort(ids)
	if page.Total != len(ids) {
		t.Errorf("total = %d over %d runs; a count must not leak runs out of scope", page.Total, len(ids))
	}
	return ids
}

// API-035: every ledger read answers only the runs in the viewer's scope.
func TestAPI035ReadsAnswerOnlyTheViewersOrganisations(t *testing.T) {
	h := newScopeHarness(t)

	h.as(inA, inB)
	if got, want := h.runIDs(t), []string{"run-000", "run-001", "run-003"}; !slices.Equal(got, want) {
		t.Errorf("A (operator) and B see %v, want %v", got, want)
	}

	h.as(inC)
	if got, want := h.runIDs(t), []string{"run-002"}; !slices.Equal(got, want) {
		t.Errorf("C sees %v, want %v", got, want)
	}

	var repos RepoList
	decodeBody(t, get(t, h.srv.URL, "/api/v1/repos", h.cookie), &repos)
	if len(repos.Repos) != 1 || repos.Repos[0].Repo != "github.com/innsegl/one" ||
		repos.Repos[0].Runs != 1 || repos.Repos[0].Commits != 2 {
		t.Errorf("C's repositories = %+v, want one with 1 run and 2 commits", repos.Repos)
	}

	var o Overview
	decodeBody(t, get(t, h.srv.URL, "/api/v1/overview", h.cookie), &o)
	if total := o.ActiveRuns + o.LapsedRuns + o.AbandonedRuns + o.RetiredRuns; total != 1 || o.CommitsRecorded != 2 {
		t.Errorf("C's overview counts %d runs and %d commits, want 1 and 2: %+v", total, o.CommitsRecorded, o)
	}

	ctx := WithRunScope(t.Context(), RunScope{Machines: []string{machineRunner}})
	commits, err := h.store.RecentCommits(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 1 || commits[0].CommitSHA != strings.Repeat("0", 38)+"10" {
		t.Errorf("B's recent commits = %+v, want run-001's one", commits)
	}

	records, err := contentSource{store: h.store}.RunsForPatchID(ctx, strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.RunID != "run-001" {
			t.Errorf("B's attribution names %s, a run of another organisation", r.RunID)
		}
	}
	if len(records) == 0 {
		t.Error("B's attribution names no run; run-001 recorded this change")
	}
}

// API-035, alerts: a drift alert belongs to its run; an alert with no run is
// unowned.
func TestAPI035AlertsAreScopedByTheirRun(t *testing.T) {
	h := newScopeHarness(t)
	if _, err := h.owner.Append(t.Context(), driftAlertFields("01a072b2-cdda-774e-a0e2-889ec5ac33fa",
		"scope-drift", "run-002", "spiffe://innsegl.dev/agent/fix-ci/jira-102/run-002")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.owner.Append(t.Context(), unattributedAlertFields(strings.Repeat("c", 64), 7, "scope-unattributed")); err != nil {
		t.Fatal(err)
	}
	alerts := func() []string {
		var page AlertPage
		decodeBody(t, get(t, h.srv.URL, "/api/v1/alerts", h.cookie), &page)
		var out []string
		for _, a := range page.Alerts {
			out = append(out, a.EventType)
		}
		if page.Total != len(out) {
			t.Errorf("alert total %d over %d alerts", page.Total, len(out))
		}
		return out
	}
	h.as(inB)
	if got := alerts(); len(got) != 0 {
		t.Errorf("B sees alerts %v, want none", got)
	}
	h.as(inC)
	if got := alerts(); !slices.Equal(got, []string{event.EventTypeLedgerDriftDetected}) {
		t.Errorf("C sees %v, want its run's drift alert alone", got)
	}
	h.as(inA)
	if got := alerts(); !slices.Equal(got, []string{event.EventTypeUnattributedSignatureDetected}) {
		t.Errorf("the operator sees %v, want the unowned alert alone", got)
	}
	var o Overview
	decodeBody(t, get(t, h.srv.URL, "/api/v1/overview", h.cookie), &o)
	if o.OpenAlerts != 1 {
		t.Errorf("the operator's open alerts = %d, want 1", o.OpenAlerts)
	}
}

// API-036: a run out of scope answers exactly as a run that does not exist,
// on every route under /runs/{run_id}.
func TestAPI036ARunOutOfScopeIsIndistinguishableFromNone(t *testing.T) {
	h := newScopeHarness(t)
	h.as(inB)
	for _, suffix := range []string{"", "/log", "/record", "/steps/1", "/steps/1/diff"} {
		theirs := get(t, h.srv.URL, "/api/v1/runs/run-002"+suffix, h.cookie)
		none := get(t, h.srv.URL, "/api/v1/runs/run-999"+suffix, h.cookie)
		if theirs.status != http.StatusNotFound || none.status != http.StatusNotFound {
			t.Errorf("%s: another organisation's run = %d, no run = %d; want 404 for both",
				suffix, theirs.status, none.status)
			continue
		}
		if !bytes.Equal(bytes.ReplaceAll(theirs.body, []byte("run-002"), []byte("run-999")), none.body) {
			t.Errorf("%s: the bodies differ:\n theirs %s\n none   %s", suffix, theirs.body, none.body)
		}
	}
	if a := get(t, h.srv.URL, "/api/v1/runs/run-001", h.cookie); a.status != http.StatusOK {
		t.Errorf("B's own run = %d: %s", a.status, a.body)
	}
}

// ACC-013: the scope is the viewer's live memberships, narrowed by the
// organisation the switcher chose; a choice that is not theirs narrows
// nothing.
func TestACC013TheSwitcherNarrowsTheScopeToOneOrganisation(t *testing.T) {
	h := newScopeHarness(t)
	h.as(inA, inB)
	pick := func(id string) *http.Cookie { return &http.Cookie{Name: OrganisationCookie, Value: id} }

	if got, want := h.runIDs(t, pick(orgB)), []string{"run-001"}; !slices.Equal(got, want) {
		t.Errorf("B chosen: %v, want %v", got, want)
	}
	if got, want := h.runIDs(t, pick(orgA)), []string{"run-000", "run-003"}; !slices.Equal(got, want) {
		t.Errorf("A chosen: %v, want %v", got, want)
	}
	if got, want := h.runIDs(t, pick(orgC)), []string{"run-000", "run-001", "run-003"}; !slices.Equal(got, want) {
		t.Errorf("C chosen by a member of A and B: %v, want their own %v", got, want)
	}
	if a := get(t, h.srv.URL, "/api/v1/runs/run-000", h.cookie, pick(orgB)); a.status != http.StatusNotFound {
		t.Errorf("A's run with B chosen = %d, want 404", a.status)
	}

	h.as()
	if got := h.runIDs(t); len(got) != 0 {
		t.Errorf("a person with no membership sees %v", got)
	}
}

// ACC-014: unowned runs are the operator's organisation's alone, and only
// while the deployment lets it see them.
func TestACC014UnownedRunsAreTheOperatorsByASetting(t *testing.T) {
	h := newScopeHarness(t)
	h.as(inB, inC)
	if got := h.runIDs(t); slices.Contains(got, "run-003") {
		t.Errorf("members of B and C see the unowned run: %v", got)
	}

	hidden := newScopeHarness(t, func(c *ServerConfig) { c.UnownedRunsHidden = true })
	hidden.as(inA)
	if got, want := hidden.runIDs(t), []string{"run-000"}; !slices.Equal(got, want) {
		t.Errorf("the operator with unowned runs hidden sees %v, want %v", got, want)
	}
	if a := get(t, hidden.srv.URL, "/api/v1/runs/run-003", hidden.cookie); a.status != http.StatusNotFound {
		t.Errorf("the unowned run, hidden = %d, want 404", a.status)
	}
}
