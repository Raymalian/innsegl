// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"innsegl.dev/innsegl/internal/accounts"
	"innsegl.dev/innsegl/internal/cacustody"
)

// ---------------------------------------------------------------------------
// CLI-052 (PROPOSED for doc 07's TC-CLI) — the core carries the reseal
// (#614, ADR-0082 decision 7) between the operator's machine and the
// custodian: the set the material is sealed to, the staged reseal and its
// confirm. Same guard and same rate as the unlock: only the operator's
// machine, only the route's own method.
// ---------------------------------------------------------------------------

type resealCustodian struct {
	mu  sync.Mutex
	got map[string][]byte
}

func (f *resealCustodian) record(key string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got[key] = b
}

func (f *resealCustodian) seen() map[string][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range f.got {
		out[k] = v
	}
	return out
}

func (f *resealCustodian) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = map[string][]byte{}
}

func (f *resealCustodian) server(t *testing.T) *httptest.Server {
	t.Helper()
	f.reset()
	mux := http.NewServeMux()
	mux.HandleFunc(cacustody.PathRecipients, func(w http.ResponseWriter, r *http.Request) {
		f.record(r.Method+" "+cacustody.PathRecipients, []byte{})
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"recipients":["age1a"],"digest":"sha256:d","recorded":true}`)); err != nil {
			t.Error(err)
		}
	})
	for _, p := range []string{cacustody.PathReseal, cacustody.PathResealConfirm} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			f.record(r.Method+" "+p, b)
			if p == cacustody.PathReseal {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(`{"set_digest":"sha256:d"}`)); err != nil {
					t.Error(err)
				}
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCLI052TheCoreCarriesTheResealForTheOperatorsMachineOnly(t *testing.T) {
	f := &resealCustodian{}
	srv := f.server(t)
	h := caCustodyHandler(srv.URL, operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))

	rec := custodyReq(t, h, http.MethodGet, cacustody.CoreRecipientsPath, "inst-1", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"age1a"`) {
		t.Fatalf("recipients: %d %s", rec.Code, rec.Body)
	}
	body := []byte(`{"opener_recipient":"age1a","recipients":["age1a"],"set_digest":"sha256:d"}`)
	rec = custodyReq(t, h, http.MethodPost, cacustody.CoreResealPath, "inst-1", body)
	if got := f.seen()["POST "+cacustody.PathReseal]; rec.Code != http.StatusOK || !bytes.Equal(got, body) {
		t.Fatalf("reseal: %d %s, custodian got %q", rec.Code, rec.Body, got)
	}
	confirm := []byte(`{"check":"c","set_digest":"sha256:d"}`)
	rec = custodyReq(t, h, http.MethodPost, cacustody.CoreResealConfirmPath, "inst-1", confirm)
	if got := f.seen()["POST "+cacustody.PathResealConfirm]; rec.Code != http.StatusNoContent || !bytes.Equal(got, confirm) {
		t.Fatalf("confirm: %d %s, custodian got %q", rec.Code, rec.Body, got)
	}

	f.reset()
	member := func() *fakeBackupStore {
		s := operatorMachine()
		s.members[0].Role = accounts.RoleMember
		return s
	}
	service := func() *fakeBackupStore {
		s := operatorMachine()
		s.inst.Kind = accounts.KindService
		return s
	}
	for name, c := range map[string]struct {
		store        func() *fakeBackupStore
		method, path string
		installation string
		want         int
	}{
		"no certificate":         {operatorMachine, http.MethodPost, cacustody.CoreResealPath, "", http.StatusUnauthorized},
		"unknown machine":        {operatorMachine, http.MethodGet, cacustody.CoreRecipientsPath, "inst-2", http.StatusUnauthorized},
		"a GET of the reseal":    {operatorMachine, http.MethodGet, cacustody.CoreResealPath, "inst-1", http.StatusMethodNotAllowed},
		"a GET of the confirm":   {operatorMachine, http.MethodGet, cacustody.CoreResealConfirmPath, "inst-1", http.StatusMethodNotAllowed},
		"a POST of the set":      {operatorMachine, http.MethodPost, cacustody.CoreRecipientsPath, "inst-1", http.StatusMethodNotAllowed},
		"a deeper confirm path":  {operatorMachine, http.MethodPost, cacustody.CoreResealConfirmPath + "/x", "inst-1", http.StatusNotFound},
		"a member, not an owner": {member, http.MethodPost, cacustody.CoreResealPath, "inst-1", http.StatusForbidden},
		"a service installation": {service, http.MethodPost, cacustody.CoreResealConfirmPath, "inst-1", http.StatusForbidden},
	} {
		guarded := caCustodyHandler(srv.URL, c.store(), newBackupLimiter(nil), newServeLog(io.Discard))
		if got := custodyReq(t, guarded, c.method, c.path, c.installation, []byte("{}")); got.Code != c.want {
			t.Errorf("%s: %d %s, want %d", name, got.Code, got.Body, c.want)
		}
	}
	if got := f.seen(); len(got) != 0 {
		t.Fatalf("a refused caller reached the custodian: %v", got)
	}

	// Custody off: no reseal routes, and nothing forwarded.
	off := caCustodyHandler("", operatorMachine(), newBackupLimiter(nil), newServeLog(io.Discard))
	for p, m := range map[string]string{cacustody.CoreRecipientsPath: http.MethodGet,
		cacustody.CoreResealPath: http.MethodPost, cacustody.CoreResealConfirmPath: http.MethodPost} {
		if got := custodyReq(t, off, m, p, "inst-1", []byte("{}")); got.Code != http.StatusNotFound {
			t.Errorf("%s with custody off: %d", p, got.Code)
		}
	}

	// An oversized reseal never reaches the custodian.
	rec = custodyReq(t, h, http.MethodPost, cacustody.CoreResealPath, "inst-1", bytes.Repeat([]byte("x"), 1<<20))
	if _, sent := f.seen()["POST "+cacustody.PathReseal]; rec.Code != http.StatusRequestEntityTooLarge || sent {
		t.Fatalf("an oversized reseal: %d, forwarded %v", rec.Code, sent)
	}

	// The same limit as the unlock: a burst is refused at the core.
	limited := caCustodyHandler(srv.URL, operatorMachine(), newCustodyLimiter(nil), newServeLog(io.Discard))
	var last int
	for range custodyBurst + 1 {
		last = custodyReq(t, limited, http.MethodGet, cacustody.CoreRecipientsPath, "inst-1", nil).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("request %d in a burst: %d, want 429", custodyBurst+1, last)
	}
}
