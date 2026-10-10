// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/webauthntest"
)

// RM-333 (#511), ADR-0062's 2026-10-03 amendment: the account page shows
// the organisation and role, its machines, repositories and agents, and the
// person's own sign-ins; a machine is connected (an enrolment token minted)
// or revoked only after a fresh passkey ceremony, by an owner or an admin.
//
// The server, the session, the passkeys and the ledger are real (Postgres,
// the software authenticator). The accounts spine is the one stand-in:
// internal/accounts imports this package, so its Store cannot be built here;
// internal/accounts/organisations_test.go runs the same contract against a
// real Postgres.

type fakeOrgs struct {
	mu          sync.Mutex
	memberships map[string][]OrgMembership
	machines    []OrgMachine
	grants      []OrgRepoGrant
	minted      []string // accountID|actor|kind|repos
	revoked     []string
	err         error // answered by every call when set
	mintErr     error
	revokeErr   error
	founded     int // FoundOperator calls

	// Members, roles and invitations (#480, #481): accountmembers_test.go.
	members   map[string][]OrgMember // by account
	invites   map[string]*fakeInvite // by code
	changes   []string               // what SetRole, RemoveMember and the invitations were asked
	memberErr error                  // answered by every member change when set
	ownerDSN  string                 // the real database a new user is created in
}

func (f *fakeOrgs) FoundOperator(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.founded++
	return f.founded == 1, f.err
}

func (f *fakeOrgs) Memberships(_ context.Context, userID string) ([]OrgMembership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.memberships[userID], nil
}

func (f *fakeOrgs) Machines(_ context.Context, accountIDs []string) ([]OrgMachine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []OrgMachine
	for _, m := range f.machines {
		if slices.Contains(accountIDs, m.AccountID) {
			out = append(out, m)
		}
	}
	return out, nil
}

func (f *fakeOrgs) RepoGrants(_ context.Context, accountIDs []string) ([]OrgRepoGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []OrgRepoGrant
	for _, g := range f.grants {
		if slices.Contains(accountIDs, g.AccountID) {
			out = append(out, g)
		}
	}
	return out, nil
}

func (f *fakeOrgs) RevokeMachine(_ context.Context, machineID, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokeErr != nil {
		return f.revokeErr
	}
	for i := range f.machines {
		if f.machines[i].ID != machineID {
			continue
		}
		if f.machines[i].Status == "revoked" {
			return ErrMachineRevoked
		}
		now := time.Now().UTC()
		f.machines[i].Status, f.machines[i].RevokedAt = "revoked", &now
		f.revoked = append(f.revoked, machineID+"|"+actor)
		return nil
	}
	return ErrMachineNotFound
}

func (f *fakeOrgs) MintEnrolmentToken(_ context.Context, accountID, actor, kind string, repos []string) (string, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mintErr != nil {
		return "", time.Time{}, f.mintErr
	}
	f.minted = append(f.minted, accountID+"|"+actor+"|"+kind+"|"+strings.Join(repos, ","))
	return "ie_0123456789abcdef_" + strings.Repeat("9", 64), time.Now().Add(15 * time.Minute).UTC(), nil
}

const (
	orgA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	orgB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	orgC = "cccccccccccccccccccccccccccccccc"

	machineLaptop = "11111111111111111111111111111111"
	machineRunner = "22222222222222222222222222222222"
	machineOther  = "33333333333333333333333333333333"
)

type orgHarness struct {
	srv       *httptest.Server
	authStore *AuthStore
	ownerDSN  string
	orgs      *fakeOrgs
	auth      *webauthntest.Authenticator
	cookie    *http.Cookie
	userID    string
	owner     *ledger.Store // the ledger, written as its owner (scope_test.go)
	store     *Store        // the query API's read-only store
}

// newOrgHarness signs a user in and makes them role in organisation A and a
// member of organisation B. Organisation C is someone else's.
func newOrgHarness(t *testing.T, role string, withOrgs bool, opts ...func(*ServerConfig)) orgHarness {
	t.Helper()
	m := migratedWithRoles(t)
	seed(t, m.owner, 4)
	store, _ := readStore(t, m.readerDSN)
	authStore, err := OpenAuthStore(context.Background(), m.authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(authStore.Close)

	orgs := &fakeOrgs{memberships: map[string][]OrgMembership{}, ownerDSN: m.ownerDSN}
	cfg := ServerConfig{
		Store: store, Prover: newProofScenario(t, proofOptions{}).prover(t),
		AuthStore: authStore, WebAuthn: testWebAuthnConfig,
	}
	if withOrgs {
		cfg.Organisations = orgs
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)

	auth, cookie := enrolTestUser(t, listening.URL, authStore)
	userID, _, ok := verifySessionToken(t, authStore, cookie.Value)
	if !ok {
		t.Fatal("the enrolling session does not verify")
	}
	enrolled := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	renewed := enrolled.Add(48 * time.Hour)
	orgs.memberships[userID] = []OrgMembership{
		{AccountID: orgA, Name: "example-org", Operator: true, Role: role},
		{AccountID: orgB, Name: "example-team", Role: roleMember},
	}
	orgs.machines = []OrgMachine{
		{ID: machineLaptop, AccountID: orgA, Name: "laptop", Kind: "workstation", Repos: []string{"*"},
			Status: "active", CreatedAt: enrolled, LastRenewedAt: &renewed},
		{ID: machineRunner, AccountID: orgB, Name: "build-runner-1", Kind: "service",
			Repos: []string{"github.com/innsegl/two"}, Status: "active", CreatedAt: enrolled.Add(time.Hour)},
		{ID: machineOther, AccountID: orgC, Name: "not-yours", Kind: "workstation", Repos: []string{"*"},
			Status: "active", CreatedAt: enrolled},
	}
	orgs.grants = []OrgRepoGrant{
		{AccountID: orgA, Repo: "github.com/innsegl/one", Since: enrolled},
		{AccountID: orgA, Repo: "github.com/example/quiet", Since: enrolled},
		{AccountID: orgC, Repo: "github.com/innsegl/two", Since: enrolled},
	}
	return orgHarness{
		srv: listening, authStore: authStore, ownerDSN: m.ownerDSN, orgs: orgs,
		auth: auth, cookie: cookie, userID: userID, owner: m.owner, store: store,
	}
}

// confirm is begin, a passkey assertion with auth, and finish, for one of the
// passkey-confirmed account routes ("machines/revoke", "enrolment-tokens").
func (h orgHarness) confirm(t *testing.T, route string, body any, auth *webauthntest.Authenticator) answer {
	t.Helper()
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/"+route+"/begin", mustJSON(t, body), h.cookie)
	if begin.status != http.StatusOK {
		return begin
	}
	return h.finish(t, route, h.assertion(t, begin, auth))
}

func (h orgHarness) assertion(t *testing.T, begin answer, auth *webauthntest.Authenticator) string {
	t.Helper()
	var challenge loginCeremonyResponse
	decodeBody(t, begin, &challenge)
	credential, err := auth.Assert(challenge.CredentialAssertion, testWebAuthnConfig.RPOrigin, h.userID)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	return mustJSON(t, map[string]any{"ceremony_id": challenge.CeremonyID, "credential": json.RawMessage(credential)})
}

func (h orgHarness) finish(t *testing.T, route, body string) answer {
	t.Helper()
	return do(t, http.MethodPost, h.srv.URL+"/api/v1/account/"+route+"/finish", body, h.cookie)
}

func (h orgHarness) authEventDetails(t *testing.T) string {
	t.Helper()
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	rows, err := c.Query(ctx, `SELECT event_type || ':' || detail FROM innsegl_auth.auth_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return strings.Join(out, "\n")
}

func TestRM333AccountNamesOrganisationsRolesAndPrivileges(t *testing.T) {
	h := newOrgHarness(t, roleAdmin, true)
	acc := getAccount(t, h.srv.URL, h.cookie)
	if len(acc.Organisations) != 2 {
		t.Fatalf("organisations = %+v", acc.Organisations)
	}
	a, b := acc.Organisations[0], acc.Organisations[1]
	if a.ID != orgA || a.Name != "example-org" || a.Role != roleAdmin || !a.Operator {
		t.Errorf("first organisation = %+v", a)
	}
	allowed := func(o AccountOrganisation) map[string]bool {
		out := map[string]bool{}
		for _, p := range o.Privileges {
			out[p.Action] = p.Allowed
		}
		return out
	}
	pa, pb := allowed(a), allowed(b)
	if len(pa) != len(privilegeActions) {
		t.Fatalf("privileges = %+v", a.Privileges)
	}
	for action, want := range map[string]bool{
		PrivilegeReadLedger: true, PrivilegeResolveAlerts: true, PrivilegeManageOwnSignIn: true,
		PrivilegeConnectMachine: true, PrivilegeRevokeMachine: true,
		PrivilegeGrantRepositories: false, PrivilegeManageMembers: true,
	} {
		if pa[action] != want {
			t.Errorf("admin %s = %v, want %v", action, pa[action], want)
		}
	}
	if !pb[PrivilegeConnectMachine] || pb[PrivilegeRevokeMachine] || pb[PrivilegeManageMembers] || !pb[PrivilegeReadLedger] {
		t.Errorf("member privileges = %+v", b.Privileges)
	}
}

func TestRM333RolePrivilegesTable(t *testing.T) {
	for _, tc := range []struct {
		role, action string
		want         bool
	}{
		{roleOwner, PrivilegeConnectMachine, true},
		{roleAdmin, PrivilegeRevokeMachine, true},
		{roleMember, PrivilegeConnectMachine, true},
		{roleMember, PrivilegeRevokeMachine, false},
		{roleAdmin, PrivilegeManageOwners, false},
		{roleOwner, PrivilegeEraseOrganisation, true},
		{roleMember, PrivilegeResolveAlerts, true},
		{roleOwner, PrivilegeGrantRepositories, false},
		{roleOwner, PrivilegeManageMembers, true},
		{"stranger", PrivilegeReadLedger, false},
		{roleOwner, "unknown", false},
	} {
		if got := roleMay(tc.role, tc.action); got != tc.want {
			t.Errorf("roleMay(%s, %s) = %v, want %v", tc.role, tc.action, got, tc.want)
		}
	}
}

func TestRM333WithoutAnAccountsStoreTheOrganisationRoutesSayUnavailable(t *testing.T) {
	h := newOrgHarness(t, roleOwner, false)
	acc := getAccount(t, h.srv.URL, h.cookie)
	if acc.Organisations == nil || len(acc.Organisations) != 0 {
		t.Errorf("organisations = %#v, want an empty list", acc.Organisations)
	}
	for _, path := range []string{"/api/v1/account/machines", "/api/v1/account/repositories", "/api/v1/account/agents"} {
		if a := get(t, h.srv.URL, path, h.cookie); a.status != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want 503: %s", path, a.status, a.body)
		}
	}
	for _, path := range []string{"/api/v1/account/machines/revoke/begin", "/api/v1/account/enrolment-tokens/begin",
		"/api/v1/account/machines/revoke/finish", "/api/v1/account/enrolment-tokens/finish"} {
		if a := do(t, http.MethodPost, h.srv.URL+path, "{}", h.cookie); a.status != http.StatusServiceUnavailable {
			t.Errorf("POST %s = %d, want 503: %s", path, a.status, a.body)
		}
	}
}

func TestRM333MachinesAreTheUsersOrganisationsWithLastRun(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	insertMapping(t, h.ownerDSN, "run-000", machineLaptop)
	insertMapping(t, h.ownerDSN, "run-001", machineLaptop)

	a := get(t, h.srv.URL, "/api/v1/account/machines", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET machines: %d: %s", a.status, a.body)
	}
	var got AccountMachines
	decodeBody(t, a, &got)
	if len(got.Machines) != 2 {
		t.Fatalf("machines = %+v", got.Machines)
	}
	laptop, runner := got.Machines[0], got.Machines[1]
	if laptop.ID != machineLaptop || laptop.Organisation != "example-org" || !laptop.CanManage ||
		laptop.LastRenewedAt == nil || laptop.LastRunAt == nil || laptop.EnrolledAt.IsZero() {
		t.Errorf("laptop = %+v", laptop)
	}
	if runner.ID != machineRunner || runner.CanManage || runner.LastRunAt != nil || runner.Kind != "service" {
		t.Errorf("runner = %+v", runner)
	}
}

func TestRM333MintingATokenTakesAFreshPasskeyCeremony(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	a := h.confirm(t, "enrolment-tokens", EnrolmentTokenRequest{OrganisationID: orgA}, h.auth)
	if a.status != http.StatusOK {
		t.Fatalf("mint: %d: %s", a.status, a.body)
	}
	var tok EnrolmentToken
	decodeBody(t, a, &tok)
	if !strings.HasPrefix(tok.Token, "ie_") || tok.ExpiresAt.IsZero() || tok.OrganisationID != orgA ||
		tok.Kind != "workstation" || !slices.Equal(tok.Repos, []string{"*"}) {
		t.Fatalf("token = %+v", tok)
	}
	if cc := a.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if want := orgA + "|" + h.userID + "|workstation|*"; len(h.orgs.minted) != 1 || h.orgs.minted[0] != want {
		t.Errorf("minted = %v, want [%s]", h.orgs.minted, want)
	}
	events := h.authEventDetails(t)
	if !strings.Contains(events, AuthEventEnrolmentTokenMinted+":") {
		t.Errorf("no %s auth event:\n%s", AuthEventEnrolmentTokenMinted, events)
	}
	if strings.Contains(events, tok.Token) || strings.Contains(events, strings.Repeat("9", 64)) {
		t.Errorf("the token reached the auth events:\n%s", events)
	}

	svc := h.confirm(t, "enrolment-tokens", EnrolmentTokenRequest{OrganisationID: orgA, Kind: "service",
		Repos: []string{"github.com/innsegl/one"}}, h.auth)
	if svc.status != http.StatusOK {
		t.Fatalf("mint a service token: %d: %s", svc.status, svc.body)
	}
	if want := orgA + "|" + h.userID + "|service|github.com/innsegl/one"; h.orgs.minted[1] != want {
		t.Errorf("minted = %v", h.orgs.minted)
	}
}

func TestRM333MintingWithoutAFreshPasskeyCeremonyIsRefused(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)

	// No ceremony at all.
	if a := h.finish(t, "enrolment-tokens", `{"ceremony_id":"nope","credential":{}}`); a.status != http.StatusUnauthorized {
		t.Errorf("finish without a ceremony = %d, want 401: %s", a.status, a.body)
	}

	// A ceremony answered by a passkey that is not this account's.
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if begin.status != http.StatusOK {
		t.Fatalf("begin: %d: %s", begin.status, begin.body)
	}
	if a := h.finish(t, "enrolment-tokens", h.assertion(t, begin, newSoftAuthenticator(t))); a.status != http.StatusUnauthorized {
		t.Errorf("a stranger's passkey = %d, want 401: %s", a.status, a.body)
	}

	// A ceremony used once cannot be used again.
	begin = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	body := h.assertion(t, begin, h.auth)
	if a := h.finish(t, "enrolment-tokens", body); a.status != http.StatusOK {
		t.Fatalf("first finish: %d: %s", a.status, a.body)
	}
	if a := h.finish(t, "enrolment-tokens", body); a.status != http.StatusUnauthorized {
		t.Errorf("a replayed ceremony = %d, want 401: %s", a.status, a.body)
	}

	// A revoke ceremony cannot mint, and a mint ceremony cannot revoke.
	revoke := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/revoke/begin",
		mustJSON(t, MachineRevokeRequest{MachineID: machineLaptop}), h.cookie)
	if revoke.status != http.StatusOK {
		t.Fatalf("revoke begin: %d: %s", revoke.status, revoke.body)
	}
	if a := h.finish(t, "enrolment-tokens", h.assertion(t, revoke, h.auth)); a.status != http.StatusUnauthorized {
		t.Errorf("a revoke ceremony finishing a mint = %d, want 401: %s", a.status, a.body)
	}
	if len(h.orgs.minted) != 1 || len(h.orgs.revoked) != 0 {
		t.Errorf("minted %v revoked %v; only the one confirmed mint should have happened", h.orgs.minted, h.orgs.revoked)
	}
	if !strings.Contains(h.authEventDetails(t), AuthEventConfirmationRefused+":") {
		t.Error("the refused passkey left no auth event")
	}
}

// ACC-004 (plan, Authorization E1): a member connects machines of their own
// and revokes only those; everyone else's needs an owner or an admin.
func TestACC004MembersConnectTheirOwnMachinesAndRevokeOnlyThose(t *testing.T) {
	h := newOrgHarness(t, roleMember, true)
	a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if a.status != http.StatusOK {
		t.Errorf("member mint = %d, want a passkey challenge: %s", a.status, a.body)
	}
	a = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/revoke/begin",
		mustJSON(t, MachineRevokeRequest{MachineID: machineLaptop}), h.cookie)
	if a.status != http.StatusForbidden || !strings.Contains(string(a.body), "owner or an admin") {
		t.Errorf("member revoke of someone else's machine = %d: %s", a.status, a.body)
	}
	h.orgs.mu.Lock()
	h.orgs.machines[0].CreatedBy = h.userID
	h.orgs.mu.Unlock()
	machines := do(t, http.MethodGet, h.srv.URL+"/api/v1/account/machines", "", h.cookie)
	var listed AccountMachines
	decodeBody(t, machines, &listed)
	if len(listed.Machines) == 0 || listed.Machines[0].ID != machineLaptop || !listed.Machines[0].CanManage {
		t.Errorf("their own machine is not manageable: %+v", listed.Machines)
	}
	if r := h.confirm(t, "machines/revoke", MachineRevokeRequest{MachineID: machineLaptop}, h.auth); r.status != http.StatusOK {
		t.Errorf("member revoke of their own machine = %d: %s", r.status, r.body)
	}
	// Organisation C is not theirs at all.
	a = do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgC}), h.cookie)
	if a.status != http.StatusForbidden {
		t.Errorf("mint for a stranger's organisation = %d: %s", a.status, a.body)
	}
}

// A role can change between begin and finish; finish asks again.
func TestRM333FinishChecksTheRoleAgain(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin",
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA}), h.cookie)
	if begin.status != http.StatusOK {
		t.Fatalf("begin: %d: %s", begin.status, begin.body)
	}
	body := h.assertion(t, begin, h.auth)
	h.orgs.mu.Lock()
	h.orgs.memberships[h.userID] = h.orgs.memberships[h.userID][1:]
	h.orgs.mu.Unlock()
	if a := h.finish(t, "enrolment-tokens", body); a.status != http.StatusForbidden {
		t.Errorf("finish after demotion = %d, want 403: %s", a.status, a.body)
	}
	if len(h.orgs.minted) != 0 {
		t.Errorf("minted %v after demotion", h.orgs.minted)
	}
}

func TestRM333RevokingAMachineTakesAFreshPasskeyCeremony(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	a := h.confirm(t, "machines/revoke", MachineRevokeRequest{MachineID: machineLaptop}, h.auth)
	if a.status != http.StatusOK {
		t.Fatalf("revoke: %d: %s", a.status, a.body)
	}
	var m AccountMachine
	decodeBody(t, a, &m)
	if m.ID != machineLaptop || m.Status != "revoked" || m.RevokedAt == nil {
		t.Errorf("revoked machine = %+v", m)
	}
	if len(h.orgs.revoked) != 1 || h.orgs.revoked[0] != machineLaptop+"|"+h.userID {
		t.Errorf("revoked = %v", h.orgs.revoked)
	}
	if !strings.Contains(h.authEventDetails(t), AuthEventMachineRevoked+":"+machineLaptop) {
		t.Error("no machine_revoked auth event")
	}

	// Already revoked: refused before anyone is asked for a passkey.
	again := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/revoke/begin",
		mustJSON(t, MachineRevokeRequest{MachineID: machineLaptop}), h.cookie)
	if again.status != http.StatusConflict {
		t.Errorf("revoking a revoked machine = %d, want 409: %s", again.status, again.body)
	}
	// Someone else's machine, and no machine at all, are not found.
	for _, id := range []string{machineOther, strings.Repeat("4", 32)} {
		a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/revoke/begin",
			mustJSON(t, MachineRevokeRequest{MachineID: id}), h.cookie)
		if a.status != http.StatusNotFound {
			t.Errorf("revoke %s = %d, want 404: %s", id, a.status, a.body)
		}
	}
}

func TestRM333RevokeFinishMapsTheSpinesRefusals(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrMachineRevoked, http.StatusConflict},
		{ErrMachineNotFound, http.StatusNotFound},
		{errors.New("the database went away"), http.StatusInternalServerError},
	} {
		h := newOrgHarness(t, roleOwner, true)
		h.orgs.revokeErr = tc.err
		if a := h.confirm(t, "machines/revoke", MachineRevokeRequest{MachineID: machineLaptop}, h.auth); a.status != tc.want {
			t.Errorf("%v: %d, want %d: %s", tc.err, a.status, tc.want, a.body)
		}
	}
}

func TestRM333MintFinishMapsTheSpinesRefusals(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.orgs.mintErr = ErrOrgInvalid
	if a := h.confirm(t, "enrolment-tokens", EnrolmentTokenRequest{OrganisationID: orgA}, h.auth); a.status != http.StatusBadRequest {
		t.Errorf("invalid: %d: %s", a.status, a.body)
	}
	h.orgs.mintErr = errors.New("the database went away")
	if a := h.confirm(t, "enrolment-tokens", EnrolmentTokenRequest{OrganisationID: orgA}, h.auth); a.status != http.StatusInternalServerError {
		t.Errorf("failure: %d: %s", a.status, a.body)
	}
}

func TestRM333MintBeginRefusesABadRequest(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	for _, body := range []string{
		mustJSON(t, EnrolmentTokenRequest{OrganisationID: orgA, Kind: "toaster"}),
		mustJSON(t, EnrolmentTokenRequest{}),
		`not json`,
	} {
		a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/enrolment-tokens/begin", body, h.cookie)
		if a.status != http.StatusBadRequest && a.status != http.StatusForbidden {
			t.Errorf("%s = %d: %s", body, a.status, a.body)
		}
	}
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/machines/revoke/begin", `not json`, h.cookie); a.status != http.StatusBadRequest {
		t.Errorf("revoke with a bad body = %d", a.status)
	}
	if a := h.finish(t, "machines/revoke", `not json`); a.status != http.StatusBadRequest {
		t.Errorf("revoke finish with a bad body = %d", a.status)
	}
}

func TestRM333OrganisationReadFailuresAreServerErrors(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.orgs.err = errors.New("the database went away")
	if a := get(t, h.srv.URL, "/api/v1/account", h.cookie); a.status != http.StatusInternalServerError {
		t.Errorf("GET account = %d", a.status)
	}
	for _, path := range []string{"/api/v1/account/machines", "/api/v1/account/repositories", "/api/v1/account/agents"} {
		if a := get(t, h.srv.URL, path, h.cookie); a.status != http.StatusInternalServerError {
			t.Errorf("GET %s = %d, want 500", path, a.status)
		}
	}
	for _, route := range []string{"machines/revoke", "enrolment-tokens"} {
		a := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/"+route+"/begin",
			mustJSON(t, map[string]string{"machine_id": machineLaptop, "organisation_id": orgA}), h.cookie)
		if a.status != http.StatusInternalServerError {
			t.Errorf("POST %s/begin = %d, want 500", route, a.status)
		}
	}
}

func TestRM333SessionsMarkThisBrowserAndSignOutTheOthers(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	otherToken, _, err := h.authStore.CreateSession(context.Background(), h.userID, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other := &http.Cookie{Name: sessionCookieName, Value: otherToken}

	a := get(t, h.srv.URL, "/api/v1/account/sessions", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET sessions: %d: %s", a.status, a.body)
	}
	var list AccountSessions
	decodeBody(t, a, &list)
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions = %+v", list.Sessions)
	}
	var current, recovery int
	for _, s := range list.Sessions {
		if s.Current {
			current++
			if s.PasskeyName == nil {
				t.Error("this browser signed in with a passkey and names none")
			}
		}
		if s.PasskeyName == nil {
			recovery++
		}
		if len(s.ID) != 12 || strings.Contains(string(a.body), hashToken(otherToken)) {
			t.Errorf("session id %q", s.ID)
		}
	}
	if current != 1 || recovery != 1 {
		t.Errorf("current %d, without a passkey %d: %+v", current, recovery, list.Sessions)
	}

	out := do(t, http.MethodPost, h.srv.URL+"/api/v1/account/sessions/sign-out-others", "{}", h.cookie)
	if out.status != http.StatusOK {
		t.Fatalf("sign out others: %d: %s", out.status, out.body)
	}
	var signedOut SignedOut
	decodeBody(t, out, &signedOut)
	if signedOut.SignedOut != 1 {
		t.Errorf("signed_out = %d, want 1", signedOut.SignedOut)
	}
	if a := get(t, h.srv.URL, "/api/v1/account", other); a.status != http.StatusUnauthorized {
		t.Errorf("the other sign-in still works: %d", a.status)
	}
	if a := get(t, h.srv.URL, "/api/v1/account", h.cookie); a.status != http.StatusOK {
		t.Errorf("this sign-in stopped working: %d", a.status)
	}
	if !strings.Contains(h.authEventDetails(t), AuthEventOtherSessionsSignedOut+":1") {
		t.Error("no auth event for signing the others out")
	}
}

func TestRM333RepositoriesJoinGrantsWithLedgerActivity(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	a := get(t, h.srv.URL, "/api/v1/account/repositories", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET repositories: %d: %s", a.status, a.body)
	}
	var got AccountRepositories
	decodeBody(t, a, &got)
	if len(got.Repositories) != 2 {
		t.Fatalf("repositories = %+v", got.Repositories)
	}
	byRepo := map[string]AccountRepository{}
	for _, r := range got.Repositories {
		byRepo[r.Repo] = r
	}
	one, quiet := byRepo["github.com/innsegl/one"], byRepo["github.com/example/quiet"]
	if one.Runs == 0 || one.LastEventAt == nil || one.Organisation != "example-org" || one.Since.IsZero() {
		t.Errorf("one = %+v", one)
	}
	if quiet.Runs != 0 || quiet.Commits != 0 || quiet.LastEventAt != nil {
		t.Errorf("quiet = %+v", quiet)
	}
	if _, ok := byRepo["github.com/innsegl/two"]; ok {
		t.Error("a repository another organisation holds was listed")
	}
}

func TestRM333AgentsAreTheRunsMappedToTheOrganisationsMachines(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	insertMapping(t, h.ownerDSN, "run-000", machineLaptop)
	insertMapping(t, h.ownerDSN, "run-001", machineRunner)
	insertMapping(t, h.ownerDSN, "run-002", machineOther)

	a := get(t, h.srv.URL, "/api/v1/account/agents", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET agents: %d: %s", a.status, a.body)
	}
	var got AccountAgents
	decodeBody(t, a, &got)
	if len(got.RecentRuns) != 2 {
		t.Fatalf("recent runs = %+v", got.RecentRuns)
	}
	names := map[string]string{}
	for _, r := range got.RecentRuns {
		names[r.RunID] = r.MachineName
		if r.AgentType == "" || r.RegisteredAt.IsZero() {
			t.Errorf("run = %+v", r)
		}
	}
	if names["run-000"] != "laptop" || names["run-001"] != "build-runner-1" {
		t.Errorf("machine names = %v", names)
	}
	if !got.RecentRuns[0].RegisteredAt.After(got.RecentRuns[1].RegisteredAt) &&
		!got.RecentRuns[0].RegisteredAt.Equal(got.RecentRuns[1].RegisteredAt) {
		t.Error("recent runs are not newest first")
	}
	total := 0
	for _, at := range got.AgentTypes {
		total += at.Runs
		if at.LastRegisteredAt.IsZero() {
			t.Errorf("agent type = %+v", at)
		}
	}
	if total != 2 || len(got.AgentTypes) != 2 {
		t.Errorf("agent types = %+v", got.AgentTypes)
	}
}

func TestRM333NoMachinesMeansNoAgents(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.orgs.machines = nil
	a := get(t, h.srv.URL, "/api/v1/account/agents", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET agents: %d", a.status)
	}
	var got AccountAgents
	decodeBody(t, a, &got)
	if got.AgentTypes == nil || got.RecentRuns == nil || len(got.RecentRuns) != 0 {
		t.Errorf("agents = %#v", got)
	}
}

// insertMapping writes one gateway run mapping row naming machine as the
// client, as the gateway does for a run it maps (GW-019).
func insertMapping(t *testing.T, ownerDSN, runID, machine string) {
	t.Helper()
	c, ctx := ownerConnAPI(t, ownerDSN)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl.gateway_run_mapping (run_id, session_id, agent_id, client_id)
		VALUES ($1, $2, 'main', $3)`, runID, "session-"+runID, machine); err != nil {
		t.Fatalf("insert mapping: %v", err)
	}
}

// ownerConnAPI is one owner connection, closed at cleanup.
func ownerConnAPI(t *testing.T, ownerDSN string) (*pgx.Conn, context.Context) {
	t.Helper()
	ctx := t.Context()
	c, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connect as owner: %v", err)
	}
	t.Cleanup(func() { discardError(c.Close(context.Background())) })
	return c, ctx
}

var errMachinesGone = errors.New("the machines went away")

// The first user's enrolment founds the deployment's own organisation, so a
// fresh install's account page has one to connect machines from.
func TestFirstEnrolmentFoundsTheOperatorOrganisation(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	h.orgs.mu.Lock()
	defer h.orgs.mu.Unlock()
	if h.orgs.founded != 1 {
		t.Fatalf("FoundOperator calls after the first enrolment = %d, want 1", h.orgs.founded)
	}
}

// The account page's connect command pins the core by its CA's fingerprint,
// read from the CA certificate the gateway writes, so a person copies a
// command that works rather than one with a placeholder in it.
func TestMachinesAnswerTheCoreCAFingerprint(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "gateway-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	want := "sha256:" + hex.EncodeToString(sum[:])

	h := newOrgHarness(t, roleOwner, true, func(c *ServerConfig) { c.CoreCACertFile = caFile })
	a := get(t, h.srv.URL, "/api/v1/account/machines", h.cookie)
	var got AccountMachines
	decodeBody(t, a, &got)
	if got.CAFingerprint != want {
		t.Fatalf("ca_fingerprint = %q, want %q", got.CAFingerprint, want)
	}

	none := newOrgHarness(t, roleOwner, true)
	var empty AccountMachines
	decodeBody(t, get(t, none.srv.URL, "/api/v1/account/machines", none.cookie), &empty)
	if empty.CAFingerprint != "" {
		t.Fatalf("ca_fingerprint with no CA file = %q, want empty", empty.CAFingerprint)
	}
}

// A machine's last activity is the newest ledger event of any run on it,
// not when its newest run was first mapped: one long session kept a
// machine looking idle for hours.
func TestMachinesLastActivityIsTheNewestEventOfItsRuns(t *testing.T) {
	h := newOrgHarness(t, roleOwner, true)
	c, ctx := ownerConnAPI(t, h.ownerDSN)
	if _, err := c.Exec(ctx, `INSERT INTO innsegl.gateway_run_mapping (run_id, session_id, agent_id, client_id, recorded_at)
		VALUES ('run-000', 'session-run-000', 'main', $1, '2026-01-01T00:00:00Z')`, machineLaptop); err != nil {
		t.Fatalf("insert mapping: %v", err)
	}
	var newest time.Time
	if err := c.QueryRow(ctx, `SELECT max(ts) FROM innsegl.events WHERE run_id = 'run-000'`).Scan(&newest); err != nil {
		t.Fatalf("reading run-000's events: %v", err)
	}

	var got AccountMachines
	decodeBody(t, get(t, h.srv.URL, "/api/v1/account/machines", h.cookie), &got)
	laptop := got.Machines[0]
	if laptop.LastRunAt == nil || !laptop.LastRunAt.Equal(newest.UTC()) {
		t.Fatalf("laptop last activity = %v, want the newest event %v", laptop.LastRunAt, newest.UTC())
	}
}

// P1: the repositories view says, per repository, whether the core holds a
// copy in its mirror. A repository granted but never pushed is listed, and
// listed as not held, rather than dropped or shown as provable.
func TestRepositoriesSayWhetherTheCoreHoldsEachOne(t *testing.T) {
	s := newProofScenario(t, proofOptions{})
	held := staticRepos{"github.com/innsegl/one": s.repo}
	h := newOrgHarness(t, roleOwner, true, func(cfg *ServerConfig) {
		p, err := NewProver(ProofConfig{FulcioURL: s.fulcio.URL, RekorURL: s.log.URL, Repos: held})
		if err != nil {
			t.Fatalf("NewProver: %v", err)
		}
		cfg.Prover = p
	})
	a := get(t, h.srv.URL, "/api/v1/account/repositories", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET repositories: %d: %s", a.status, a.body)
	}
	if !strings.Contains(string(a.body), `"held":`) {
		t.Fatalf("the repositories answer carries no held member: %s", a.body)
	}
	var got AccountRepositories
	decodeBody(t, a, &got)
	byRepo := map[string]AccountRepository{}
	for _, r := range got.Repositories {
		byRepo[r.Repo] = r
	}
	if !byRepo["github.com/innsegl/one"].Held {
		t.Errorf("a repository the mirror holds is reported not held: %+v", byRepo["github.com/innsegl/one"])
	}
	quiet, ok := byRepo["github.com/example/quiet"]
	if !ok || quiet.Held {
		t.Errorf("a granted repository the mirror lacks = %+v (listed %v), want listed and not held", quiet, ok)
	}
}
