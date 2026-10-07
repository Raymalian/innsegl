// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/api"
	"innsegl.dev/innsegl/internal/gateway"
	"innsegl.dev/innsegl/internal/trustbackup"
)

type fakeBackupStore struct {
	inst    accounts.Installation
	instErr error
	members []api.OrgMembership
	memErr  error
}

func (f *fakeBackupStore) GetInstallation(_ context.Context, id string) (accounts.Installation, error) {
	if f.instErr != nil {
		return accounts.Installation{}, f.instErr
	}
	if id != f.inst.ID {
		return accounts.Installation{}, accounts.ErrNotFound
	}
	return f.inst, nil
}

func (f *fakeBackupStore) Memberships(_ context.Context, userID string) ([]api.OrgMembership, error) {
	if f.memErr != nil {
		return nil, f.memErr
	}
	if userID != f.inst.CreatedBy {
		return nil, nil
	}
	return f.members, nil
}

// operatorMachine is an active workstation of the operator's organisation,
// enrolled by its owner: the one shape the route serves.
func operatorMachine() *fakeBackupStore {
	return &fakeBackupStore{
		inst: accounts.Installation{ID: "inst-1", AccountID: "acct-op", CreatedBy: "u-1",
			Kind: accounts.KindWorkstation, Status: accounts.StatusActive},
		members: []api.OrgMembership{{AccountID: "acct-op", Operator: true, Role: accounts.RoleOwner}},
	}
}

func backupDirWithOne(t *testing.T) (string, trustbackup.Entry) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := &trustbackup.Store{Dir: dir, Keep: 3,
		Now: func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) }}
	e, _, err := s.Create([]age.Recipient{id.Recipient()},
		[]trustbackup.Source{trustbackup.ValueSource("a", "f", []byte("key"))})
	if err != nil {
		t.Fatal(err)
	}
	return dir, e
}

func backupGet(t *testing.T, h http.Handler, method, path, installation string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, http.NoBody)
	if installation != "" {
		req = req.WithContext(gateway.WithInstallation(req.Context(), installation))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTheCoreServesTheNewestTrustBackupToTheOperatorsMachine(t *testing.T) {
	dir, e := backupDirWithOne(t)
	h := trustBackupHandler(dir, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))

	rec := backupGet(t, h, http.MethodGet, coreTrustBackupPath, "inst-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing: %d %s", rec.Code, rec.Body)
	}
	var list trustBackupListing
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Bundles) != 1 || list.Bundles[0] != e {
		t.Fatalf("listing = %+v, want %+v", list, e)
	}

	rec = backupGet(t, h, http.MethodGet, coreTrustBackupLatestPath, "inst-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("latest: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get(headerTrustBackupName) != e.Name || rec.Header().Get(headerTrustBackupSHA256) != e.SHA256 {
		t.Fatalf("headers = %v", rec.Header())
	}
	want, err := os.ReadFile(filepath.Join(dir, e.Name))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Body.String() != string(want) {
		t.Fatal("the body is not the bundle")
	}
}

func TestTheTrustBackupRouteRefusesEveryOtherCaller(t *testing.T) {
	dir, _ := backupDirWithOne(t)
	lim := newBackupLimiter(nil)
	cases := map[string]struct {
		store        func() *fakeBackupStore
		method, path string
		installation string
		want         int
	}{
		"no certificate":     {operatorMachine, http.MethodGet, coreTrustBackupLatestPath, "", http.StatusUnauthorized},
		"unknown machine":    {operatorMachine, http.MethodGet, coreTrustBackupLatestPath, "inst-2", http.StatusUnauthorized},
		"a POST":             {operatorMachine, http.MethodPost, coreTrustBackupLatestPath, "inst-1", http.StatusMethodNotAllowed},
		"an unknown subpath": {operatorMachine, http.MethodGet, coreTrustBackupPath + "/other", "inst-1", http.StatusNotFound},
		"a store failure": {func() *fakeBackupStore {
			s := operatorMachine()
			s.instErr = errors.New("down")
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusServiceUnavailable},
		"a membership failure": {func() *fakeBackupStore {
			s := operatorMachine()
			s.memErr = errors.New("down")
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusServiceUnavailable},
		"a suspended machine": {func() *fakeBackupStore {
			s := operatorMachine()
			s.inst.Status = accounts.StatusSuspended
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusForbidden},
		"a service installation": {func() *fakeBackupStore {
			s := operatorMachine()
			s.inst.Kind = accounts.KindService
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusForbidden},
		"a member, not an owner": {func() *fakeBackupStore {
			s := operatorMachine()
			s.members[0].Role = accounts.RoleMember
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusForbidden},
		"another organisation": {func() *fakeBackupStore {
			s := operatorMachine()
			s.members[0].Operator = false
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusForbidden},
		"a membership elsewhere": {func() *fakeBackupStore {
			s := operatorMachine()
			s.members[0].AccountID = "acct-other"
			return s
		}, http.MethodGet, coreTrustBackupLatestPath, "inst-1", http.StatusForbidden},
	}
	for name, c := range cases {
		h := trustBackupHandler(dir, c.store(), lim, newServeLog(io.Discard))
		if rec := backupGet(t, h, c.method, c.path, c.installation); rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, c.want)
		}
	}
	// An admin may.
	s := operatorMachine()
	s.members[0].Role = accounts.RoleAdmin
	if rec := backupGet(t, trustBackupHandler(dir, s, lim, newServeLog(io.Discard)),
		http.MethodGet, coreTrustBackupPath, "inst-1"); rec.Code != http.StatusOK {
		t.Errorf("an admin: %d %s", rec.Code, rec.Body)
	}
}

func TestTheTrustBackupRouteSaysWhenThereIsNothingToServe(t *testing.T) {
	log := newServeLog(io.Discard)
	// A core with no backup directory configured.
	h := trustBackupHandler("", operatorMachine(), newBackupLimiter(nil), log)
	if rec := backupGet(t, h, http.MethodGet, coreTrustBackupLatestPath, "inst-1"); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "keeps no trust-key backup") {
		t.Fatalf("no dir: %d %s", rec.Code, rec.Body)
	}
	// A directory with no bundle, whose producer said why.
	dir := t.TempDir()
	st := &trustbackup.Store{Dir: dir}
	if err := st.WriteStatus(trustbackup.Status{Error: trustbackup.ErrNoRecipients.Error()}); err != nil {
		t.Fatal(err)
	}
	h = trustBackupHandler(dir, operatorMachine(), newBackupLimiter(nil), log)
	rec := backupGet(t, h, http.MethodGet, coreTrustBackupLatestPath, "inst-1")
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), trustbackup.EnvRecipients) {
		t.Fatalf("empty dir: %d %s", rec.Code, rec.Body)
	}
	rec = backupGet(t, h, http.MethodGet, coreTrustBackupPath, "inst-1")
	var list trustBackupListing
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != http.StatusOK ||
		len(list.Bundles) != 0 || list.Status == nil || list.Status.Error == "" {
		t.Fatalf("empty listing: %d %s", rec.Code, rec.Body)
	}
	// An unreadable directory is the core's fault, and says retry.
	if os.Geteuid() != 0 {
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { restoreMode(t, dir) })
		for _, p := range []string{coreTrustBackupPath, coreTrustBackupLatestPath} {
			if rec := backupGet(t, h, http.MethodGet, p, "inst-1"); rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s on an unreadable dir: %d", p, rec.Code)
			}
		}
	}
}

func TestTheTrustBackupRouteFailsCleanlyWhenTheBundleCannotBeOpened(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file; this case needs an unprivileged user")
	}
	dir, e := backupDirWithOne(t)
	if err := os.Chmod(filepath.Join(dir, e.Name), 0o000); err != nil {
		t.Fatal(err)
	}
	h := trustBackupHandler(dir, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))
	if rec := backupGet(t, h, http.MethodGet, coreTrustBackupLatestPath, "inst-1"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreadable bundle: %d %s", rec.Code, rec.Body)
	}
}

func TestTheTrustBackupRouteIsRateLimitedPerMachine(t *testing.T) {
	dir, _ := backupDirWithOne(t)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	lim := newBackupLimiter(func() time.Time { return now })
	h := trustBackupHandler(dir, operatorMachine(), lim, newServeLog(io.Discard))
	for i := 0; i < backupBurst; i++ {
		if rec := backupGet(t, h, http.MethodGet, coreTrustBackupPath, "inst-1"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	rec := backupGet(t, h, http.MethodGet, coreTrustBackupPath, "inst-1")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the burst: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	now = now.Add(backupRefill)
	if rec := backupGet(t, h, http.MethodGet, coreTrustBackupPath, "inst-1"); rec.Code != http.StatusOK {
		t.Fatalf("after a refill: %d", rec.Code)
	}
	// A refused caller does not spend a token.
	other := operatorMachine()
	other.members[0].Role = accounts.RoleMember
	hOther := trustBackupHandler(dir, other, lim, newServeLog(io.Discard))
	for i := 0; i < backupBurst+1; i++ {
		if rec := backupGet(t, hOther, http.MethodGet, coreTrustBackupPath, "inst-1"); rec.Code != http.StatusForbidden {
			t.Fatalf("refused caller %d: %d", i, rec.Code)
		}
	}
}

// Measured against the real stack pieces: the route sits behind the client
// guard, and the gateway's accounts role can read the memberships the
// decision needs. The operator organisation's owner enrolled the machine.
func TestAnEnrolledOperatorMachineFetchesTheTrustBackupThroughTheGateway(t *testing.T) {
	dir, e := backupDirWithOne(t)
	t.Setenv(envTrustBackupDir, dir)
	f := newEnFixture(t)
	pool := gwIdentityPool(t, f.ownerDSN)
	if _, err := pool.Exec(t.Context(), `UPDATE innsegl_auth.accounts SET operator = true WHERE account_id = $1`,
		f.account); err != nil {
		t.Fatal(err)
	}
	g := startHostedGateway(t, f)
	c := newEnClient(t)
	_, cert := enrol(t, f, g, c)

	get := func(client *http.Client) (int, http.Header, []byte) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			"https://"+g.addr+coreTrustBackupLatestPath, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, resp.Header, b
	}
	if status, _, _ := get(g.client(t, nil)); status != http.StatusUnauthorized {
		t.Fatalf("without a certificate: %d, want 401", status)
	}
	status, hdr, body := get(g.client(t, cert))
	if status != http.StatusOK || hdr.Get(headerTrustBackupSHA256) != e.SHA256 || int64(len(body)) != e.Size {
		t.Fatalf("with the certificate: %d %v (%d bytes)", status, hdr, len(body))
	}

	// The same machine, once its organisation is not the operator's: refused.
	if _, err := pool.Exec(t.Context(), `UPDATE innsegl_auth.accounts SET operator = false WHERE account_id = $1`,
		f.account); err != nil {
		t.Fatal(err)
	}
	if status, _, body := get(g.client(t, cert)); status != http.StatusForbidden {
		t.Fatalf("not the operator's organisation: %d %s, want 403", status, body)
	}
}

// restoreMode gives a directory a test locked back to its owner, so the
// test's cleanup can remove it.
func restoreMode(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Error(err)
	}
}
