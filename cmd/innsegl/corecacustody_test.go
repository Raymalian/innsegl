// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/cacustody"
	"innsegl.dev/innsegl/internal/gateway"
)

// ---------------------------------------------------------------------------
// OPS-147 (PROPOSED for doc 07's TC-OPS) — the core's CA-custody routes
// (#533, ADR-0076). They are the only way to the custodian from outside the
// core, and only the operator's own machine may use them: the material is
// ciphertext, but who may try to unlock the CA is the operator's decision.
// ---------------------------------------------------------------------------

type fakeCustodian struct {
	status   cacustody.Status
	material []byte
	unlocked []byte
	code     int
}

func (f *fakeCustodian) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(cacustody.PathStatus, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(f.status); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc(cacustody.PathMaterial, func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(f.material); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc(cacustody.PathUnlock, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		f.unlocked = b
		w.WriteHeader(f.code)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func custodyReq(t *testing.T, h http.Handler, method, path, installation string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, bytes.NewReader(body))
	if installation != "" {
		req = req.WithContext(gateway.WithInstallation(req.Context(), installation))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestOPS147TheCoreCarriesTheUnlockBetweenTheOperatorAndTheCustodian(t *testing.T) {
	f := &fakeCustodian{status: cacustody.Status{Initialized: true, Sealed: true},
		material: []byte("age-ciphertext"), code: http.StatusNoContent}
	srv := f.server(t)
	h := caCustodyHandler(srv.URL, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))

	rec := custodyReq(t, h, http.MethodGet, coreCACustodyPath, "inst-1", nil)
	var st caCustodyStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status: %d %s %v", rec.Code, rec.Body, err)
	}
	if !st.Enabled || !st.Sealed || !st.Initialized {
		t.Fatalf("status = %+v", st)
	}

	rec = custodyReq(t, h, http.MethodGet, coreCACustodyMaterialPath, "inst-1", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "age-ciphertext" {
		t.Fatalf("material: %d %q", rec.Code, rec.Body)
	}

	body := []byte(`{"unseal_key":"u","role_id":"r","secret_id":"s"}`)
	rec = custodyReq(t, h, http.MethodPost, coreCACustodyUnlockPath, "inst-1", body)
	if rec.Code != http.StatusNoContent || !bytes.Equal(f.unlocked, body) {
		t.Fatalf("unlock: %d, custodian got %q", rec.Code, f.unlocked)
	}

	f.code = http.StatusForbidden
	rec = custodyReq(t, h, http.MethodPost, coreCACustodyUnlockPath, "inst-1", body)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "secret_id") {
		t.Fatalf("a refused unlock: %d %s", rec.Code, rec.Body)
	}
}

func TestOPS147OnlyTheOperatorsMachineMayUseTheCustodyRoutes(t *testing.T) {
	f := &fakeCustodian{material: []byte("x"), code: http.StatusNoContent}
	srv := f.server(t)
	for name, c := range map[string]struct {
		store        func() *fakeBackupStore
		method, path string
		installation string
		want         int
	}{
		"no certificate":       {operatorMachine, http.MethodGet, coreCACustodyMaterialPath, "", http.StatusUnauthorized},
		"unknown machine":      {operatorMachine, http.MethodPost, coreCACustodyUnlockPath, "inst-2", http.StatusUnauthorized},
		"a GET of the unlock":  {operatorMachine, http.MethodGet, coreCACustodyUnlockPath, "inst-1", http.StatusMethodNotAllowed},
		"a POST of the status": {operatorMachine, http.MethodPost, coreCACustodyPath, "inst-1", http.StatusMethodNotAllowed},
		"an unknown subpath":   {operatorMachine, http.MethodGet, coreCACustodyPath + "/root", "inst-1", http.StatusNotFound},
		"a member, not an owner": {func() *fakeBackupStore {
			s := operatorMachine()
			s.members[0].Role = accounts.RoleMember
			return s
		}, http.MethodPost, coreCACustodyUnlockPath, "inst-1", http.StatusForbidden},
		"a service installation": {func() *fakeBackupStore {
			s := operatorMachine()
			s.inst.Kind = accounts.KindService
			return s
		}, http.MethodGet, coreCACustodyMaterialPath, "inst-1", http.StatusForbidden},
	} {
		h := caCustodyHandler(srv.URL, c.store(), newBackupLimiter(nil), newServeLog(io.Discard))
		if rec := custodyReq(t, h, c.method, c.path, c.installation, []byte("{}")); rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body, c.want)
		}
	}
	if f.unlocked != nil {
		t.Fatal("a refused caller reached the custodian's unlock")
	}
}

func TestOPS147ACoreWithoutCustodySaysSo(t *testing.T) {
	h := caCustodyHandler("", operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))
	rec := custodyReq(t, h, http.MethodGet, coreCACustodyPath, "inst-1", nil)
	var st caCustodyStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK || st.Enabled {
		t.Fatalf("status with custody off: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{coreCACustodyMaterialPath, coreCACustodyUnlockPath} {
		method := http.MethodGet
		if p == coreCACustodyUnlockPath {
			method = http.MethodPost
		}
		if rec := custodyReq(t, h, method, p, "inst-1", []byte("{}")); rec.Code != http.StatusNotFound {
			t.Errorf("%s with custody off: %d", p, rec.Code)
		}
	}
}

func TestOPS147AnOversizedUnlockNeverReachesTheCustodian(t *testing.T) {
	f := &fakeCustodian{code: http.StatusNoContent}
	srv := f.server(t)
	h := caCustodyHandler(srv.URL, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))
	rec := custodyReq(t, h, http.MethodPost, coreCACustodyUnlockPath, "inst-1", bytes.Repeat([]byte("x"), 1<<20))
	if rec.Code != http.StatusRequestEntityTooLarge || f.unlocked != nil {
		t.Fatalf("an oversized unlock: %d, custodian got %d bytes", rec.Code, len(f.unlocked))
	}
}

// The client service asks for the status once a minute, every minute; the
// custody routes' limit must never refuse that cadence, or a sealed CA would
// stay sealed behind a 429.
func TestOPS147AStatusAMinuteIsNeverRateLimited(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	lim := newCustodyLimiter(func() time.Time { return now })
	for i := range 24 * 60 {
		if _, ok := lim.allow("inst-1"); !ok {
			t.Fatalf("request %d, one a minute, was refused", i)
		}
		now = now.Add(time.Minute)
	}
	for range 50 {
		lim.allow("inst-2")
	}
	if _, ok := lim.allow("inst-2"); ok {
		t.Fatal("fifty requests at once were all admitted; the limit limits nothing")
	}
}
