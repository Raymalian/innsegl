// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/webauthntest"
)

// RM-330 (#506), ADR-0044's 2026-10-03 amendment — resolving alerts from the
// dashboard.
//
// POST /api/v1/alert-resolutions/begin takes the alerts and the reason and
// answers a WebAuthn request challenge for the signed-in user's own
// passkeys; .../finish takes the assertion and, only if it verifies, writes
// the resolutions through the resolver credential. The request is held
// server-side with the ceremony, so the passkey confirms exactly what began
// it. These cases drive both calls over real HTTP with the software
// authenticator, against a real Postgres, and read the result back through
// the read-only alerts feed.

type resolutionHarness struct {
	srv       *httptest.Server
	owner     *ledger.Store
	authStore *AuthStore
	auth      *webauthntest.Authenticator
	cookie    *http.Cookie
	userID    string
	drift     []string
	unattrib  []string
}

// newResolutionHarness builds a server holding all three credentials, seeds
// n alerts of each type, and signs a user in.
func newResolutionHarness(t *testing.T, n int, withResolver bool) resolutionHarness {
	t.Helper()
	m := migratedWithRoles(t)
	drift, unattrib := seedAlerts(t, m.owner, n)
	store, _ := readStore(t, m.readerDSN)
	authStore, err := OpenAuthStore(context.Background(), m.authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(authStore.Close)

	cfg := ServerConfig{
		Store: store, Prover: newProofScenario(t, proofOptions{}).prover(t),
		AuthStore: authStore, WebAuthn: testWebAuthnConfig,
	}
	if withResolver {
		r, rerr := OpenResolver(context.Background(), m.resolverDSN)
		if rerr != nil {
			t.Fatalf("OpenResolver: %v", rerr)
		}
		t.Cleanup(r.Close)
		cfg.Resolver = r
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
	h := resolutionHarness{
		srv: listening, owner: m.owner, authStore: authStore,
		auth: auth, cookie: cookie, userID: userID,
	}
	for _, f := range drift {
		h.drift = append(h.drift, eventIDOf(t, f))
	}
	for _, f := range unattrib {
		h.unattrib = append(h.unattrib, eventIDOf(t, f))
	}
	return h
}

func eventIDOf(t *testing.T, f event.Fields) string {
	t.Helper()
	id, ok := f[event.FieldEventID].(string)
	if !ok {
		t.Fatalf("event carries no string event_id: %+v", f)
	}
	return id
}

func (h resolutionHarness) begin(t *testing.T, ids []string, reason string) answer {
	t.Helper()
	return do(t, http.MethodPost, h.srv.URL+"/api/v1/alert-resolutions/begin",
		mustJSON(t, ResolveRequest{EventIDs: ids, Reason: reason}), h.cookie)
}

// assert answers a begin's challenge with auth, as userHandle.
func (h resolutionHarness) assert(t *testing.T, begin answer, auth *webauthntest.Authenticator, origin string) string {
	t.Helper()
	if begin.status != http.StatusOK {
		t.Fatalf("alert-resolutions/begin: %d: %s", begin.status, begin.body)
	}
	var challenge loginCeremonyResponse
	decodeBody(t, begin, &challenge)
	credential, err := auth.Assert(challenge.CredentialAssertion, origin, h.userID)
	if err != nil {
		t.Fatalf("Assert: %v", err)
	}
	return mustJSON(t, map[string]any{
		"ceremony_id": challenge.CeremonyID,
		"credential":  json.RawMessage(credential),
	})
}

func (h resolutionHarness) finish(t *testing.T, body string) answer {
	t.Helper()
	return do(t, http.MethodPost, h.srv.URL+"/api/v1/alert-resolutions/finish", body, h.cookie)
}

// resolve is begin, a passkey assertion with the enrolled authenticator, and
// finish.
func (h resolutionHarness) resolve(t *testing.T, ids []string, reason string) answer {
	t.Helper()
	return h.finish(t, h.assert(t, h.begin(t, ids, reason), h.auth, testWebAuthnConfig.RPOrigin))
}

func (h resolutionHarness) alerts(t *testing.T) map[string]Alert {
	t.Helper()
	a := get(t, h.srv.URL, "/api/v1/alerts?limit=200", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET /api/v1/alerts: %d: %s", a.status, a.body)
	}
	var page AlertPage
	decodeBody(t, a, &page)
	out := map[string]Alert{}
	for _, al := range page.Alerts {
		out[al.EventID] = al
	}
	return out
}

func TestRM330ResolvingOneAlertRecordsWhoWhenAndWhy(t *testing.T) {
	h := newResolutionHarness(t, 2, true)
	target := h.drift[0]

	a := h.resolve(t, []string{target}, "the reconciler ran before the log caught up")
	if a.status != http.StatusOK {
		t.Fatalf("finish: %d: %s", a.status, a.body)
	}
	var result ResolveResult
	decodeBody(t, a, &result)
	if len(result.Resolutions) != 1 || result.Resolutions[0].EventID != target ||
		result.Resolutions[0].ResolvedBy != "Test Operator" {
		t.Fatalf("result = %+v", result)
	}

	all := h.alerts(t)
	got := all[target]
	if !got.Resolved || got.ResolvedBy != "Test Operator" ||
		got.ResolvedReason != "the reconciler ran before the log caught up" || got.ResolvedAt.IsZero() {
		t.Errorf("the alert reads back as %+v", got)
	}
	for id, al := range all {
		if id != target && al.Resolved {
			t.Errorf("alert %s was resolved too", id)
		}
	}
}

func TestRM330ResolvingAGroupResolvesEveryAlertInIt(t *testing.T) {
	h := newResolutionHarness(t, 3, true)
	a := h.resolve(t, h.unattrib, "a key rotation, reviewed")
	if a.status != http.StatusOK {
		t.Fatalf("finish: %d: %s", a.status, a.body)
	}
	all := h.alerts(t)
	for _, id := range h.unattrib {
		if !all[id].Resolved {
			t.Errorf("group member %s is still open", id)
		}
	}
	for _, id := range h.drift {
		if all[id].Resolved {
			t.Errorf("%s is outside the group and was resolved", id)
		}
	}
}

func TestRM330AResolutionWithoutAFreshPasskeyCeremonyIsRefused(t *testing.T) {
	h := newResolutionHarness(t, 1, true)
	target := []string{h.drift[0]}

	t.Run("no ceremony at all", func(t *testing.T) {
		a := h.finish(t, `{"ceremony_id":"nope","credential":{}}`)
		if a.status != http.StatusUnauthorized {
			t.Errorf("finish with no ceremony: %d, want 401: %s", a.status, a.body)
		}
	})

	t.Run("an assertion from a passkey that is not this user's", func(t *testing.T) {
		stranger := newSoftAuthenticator(t)
		a := h.finish(t, h.assert(t, h.begin(t, target, "why"), stranger, testWebAuthnConfig.RPOrigin))
		if a.status != http.StatusUnauthorized {
			t.Errorf("finish with a stranger's passkey: %d, want 401: %s", a.status, a.body)
		}
	})

	t.Run("an assertion collected at another origin", func(t *testing.T) {
		a := h.finish(t, h.assert(t, h.begin(t, target, "why"), h.auth, "https://evil.example"))
		if a.status != http.StatusUnauthorized {
			t.Errorf("finish with a cross-origin assertion: %d, want 401: %s", a.status, a.body)
		}
	})

	t.Run("a ceremony replayed", func(t *testing.T) {
		body := h.assert(t, h.begin(t, target, "why"), h.auth, testWebAuthnConfig.RPOrigin)
		if a := h.finish(t, body); a.status != http.StatusOK {
			t.Fatalf("first finish: %d: %s", a.status, a.body)
		}
		if a := h.finish(t, body); a.status != http.StatusUnauthorized {
			t.Errorf("replayed finish: %d, want 401: %s", a.status, a.body)
		}
	})

	t.Run("a sign-in ceremony cannot finish a resolution", func(t *testing.T) {
		login := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login/begin", "{}")
		a := h.finish(t, h.assert(t, login, h.auth, testWebAuthnConfig.RPOrigin))
		if a.status != http.StatusUnauthorized {
			t.Errorf("finish with a login ceremony: %d, want 401: %s", a.status, a.body)
		}
	})

	t.Run("a ceremony begun by another user's session", func(t *testing.T) {
		begin := h.begin(t, []string{h.unattrib[0]}, "why")
		body := h.assert(t, begin, h.auth, testWebAuthnConfig.RPOrigin)
		other := h
		other.cookie = recoverySession(t, h)
		if a := other.finish(t, body); a.status != http.StatusUnauthorized {
			t.Errorf("finish from another session of a different user: %d, want 401: %s", a.status, a.body)
		}
	})

	if all := h.alerts(t); all[h.unattrib[0]].Resolved {
		t.Error("a refused finish resolved an alert")
	}
}

// recoverySession is a session for a SECOND user who holds no passkey, as a
// recovery-code sign-in leaves one: created directly on the auth store.
func recoverySession(t *testing.T, h resolutionHarness) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	if err := h.authStore.CreateUser(ctx, "second-operator", "Second Operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	token, expires, err := h.authStore.CreateSession(ctx, "second-operator", "", time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: token, Expires: expires}
}

func TestRM330AUserWithNoPasskeyCannotConfirm(t *testing.T) {
	h := newResolutionHarness(t, 1, true)
	other := h
	other.cookie = recoverySession(t, h)
	a := other.begin(t, []string{h.drift[0]}, "why")
	if a.status != http.StatusForbidden {
		t.Fatalf("begin for a user with no passkey: %d, want 403: %s", a.status, a.body)
	}
	if !strings.Contains(string(a.body), "passkey") {
		t.Errorf("the refusal does not say a passkey is needed: %s", a.body)
	}
}

func TestRM330AnAlreadyResolvedAlertIsAConflict(t *testing.T) {
	h := newResolutionHarness(t, 2, true)
	if a := h.resolve(t, []string{h.drift[0]}, "first"); a.status != http.StatusOK {
		t.Fatalf("first resolve: %d: %s", a.status, a.body)
	}

	t.Run("refused at begin, before anyone is asked for a passkey", func(t *testing.T) {
		a := h.begin(t, []string{h.drift[1], h.drift[0]}, "second")
		if a.status != http.StatusConflict {
			t.Fatalf("begin over a resolved alert: %d, want 409: %s", a.status, a.body)
		}
		if !strings.Contains(string(a.body), h.drift[0]) {
			t.Errorf("the 409 does not name the resolved alert: %s", a.body)
		}
	})

	t.Run("refused at finish when someone else resolved it in between", func(t *testing.T) {
		body := h.assert(t, h.begin(t, []string{h.drift[1]}, "mine"), h.auth, testWebAuthnConfig.RPOrigin)
		if _, err := h.owner.ResolveAlert(context.Background(), h.drift[1], "kody", "the CLI got there first"); err != nil {
			t.Fatalf("ResolveAlert: %v", err)
		}
		if a := h.finish(t, body); a.status != http.StatusConflict {
			t.Errorf("finish after a concurrent resolution: %d, want 409: %s", a.status, a.body)
		}
	})
}

func TestRM330BeginRefusesWhatCouldNeverBeResolved(t *testing.T) {
	h := newResolutionHarness(t, 1, true)
	cases := []struct {
		name string
		body string
		want int
	}{
		{"not JSON", "{", http.StatusBadRequest},
		{"no alerts", mustJSON(t, ResolveRequest{Reason: "why"}), http.StatusBadRequest},
		{"no reason", mustJSON(t, ResolveRequest{EventIDs: []string{h.drift[0]}, Reason: "   "}), http.StatusBadRequest},
		{"a reason too long", mustJSON(t, ResolveRequest{EventIDs: []string{h.drift[0]}, Reason: strings.Repeat("r", 2049)}), http.StatusBadRequest},
		{"the same alert twice", mustJSON(t, ResolveRequest{EventIDs: []string{h.drift[0], h.drift[0]}, Reason: "why"}), http.StatusBadRequest},
		{"an unknown alert", mustJSON(t, ResolveRequest{EventIDs: []string{"01a072b2-cdda-774e-a0e2-889ec5ac33ff"}, Reason: "why"}), http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := do(t, http.MethodPost, h.srv.URL+"/api/v1/alert-resolutions/begin", c.body, h.cookie)
			if a.status != c.want {
				t.Errorf("begin: %d, want %d: %s", a.status, c.want, a.body)
			}
		})
	}
	t.Run("an event that is not an alert", func(t *testing.T) {
		seed(t, h.owner, 1)
		// seedAlerts appended two events; the first run event follows them.
		rec, err := h.owner.EventAt(context.Background(), 3)
		if err != nil {
			t.Fatalf("EventAt: %v", err)
		}
		a := h.begin(t, []string{eventIDOf(t, rec)}, "why")
		if a.status != http.StatusBadRequest {
			t.Errorf("begin over a %v event: %d, want 400: %s", rec[event.FieldEventType], a.status, a.body)
		}
	})
}

func TestRM330TheResolutionSurfaceGuards(t *testing.T) {
	h := newResolutionHarness(t, 1, true)
	begin := h.srv.URL + "/api/v1/alert-resolutions/begin"
	body := mustJSON(t, ResolveRequest{EventIDs: []string{h.drift[0]}, Reason: "why"})

	if a := do(t, http.MethodPost, begin, body); a.status != http.StatusUnauthorized {
		t.Errorf("begin with no session: %d, want 401", a.status)
	}
	if a := do(t, http.MethodGet, begin, "", h.cookie); a.status != http.StatusMethodNotAllowed {
		t.Errorf("GET begin: %d, want 405", a.status)
	}
	if a := do(t, http.MethodOptions, begin, "", h.cookie); a.status != http.StatusNoContent {
		t.Errorf("OPTIONS begin: %d, want 204", a.status)
	}
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/alert-resolutions/nothing", "{}", h.cookie); a.status != http.StatusNotFound {
		t.Errorf("POST an unknown resolution path: %d, want 404", a.status)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, begin, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(h.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	discardError(resp.Body.Close())
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin begin: %d, want 403", resp.StatusCode)
	}

	// The read surface stays read-only: a POST to the alerts feed is still 405.
	if a := do(t, http.MethodPost, h.srv.URL+"/api/v1/alerts", body, h.cookie); a.status != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/v1/alerts: %d, want 405", a.status)
	}
}

func TestRM330WithNoResolverCredentialResolvingIsUnavailable(t *testing.T) {
	h := newResolutionHarness(t, 1, false)
	a := h.begin(t, []string{h.drift[0]}, "why")
	if a.status != http.StatusServiceUnavailable {
		t.Fatalf("begin with no resolver: %d, want 503: %s", a.status, a.body)
	}
	if !strings.Contains(string(a.body), "resolve-alert") {
		t.Errorf("the 503 does not point at the command that still works: %s", a.body)
	}
	if a := h.finish(t, `{"ceremony_id":"x","credential":{}}`); a.status != http.StatusServiceUnavailable {
		t.Errorf("finish with no resolver: %d, want 503", a.status)
	}
}

func TestRM330HealthReportsTheResolverScope(t *testing.T) {
	h := newResolutionHarness(t, 1, true)
	a := get(t, h.srv.URL, "/api/v1/health")
	var health Health
	decodeBody(t, a, &health)
	if health.Resolver == nil || health.Resolver.Ledger.Role != ResolverRole {
		t.Fatalf("health.resolver = %+v", health.Resolver)
	}
	if health.Database.Writable() {
		t.Error("the read-only pool reports itself writable")
	}

	none := newResolutionHarness(t, 1, false)
	var bare Health
	decodeBody(t, get(t, none.srv.URL, "/api/v1/health"), &bare)
	if bare.Resolver != nil {
		t.Errorf("a server with no resolver reports one: %+v", bare.Resolver)
	}
}

// A resolver whose ledger stops answering is a 503 that says nothing was
// written — never a 404 or 409 that would read as a fact about the alert.
func TestRM330AnUnreachableLedgerIsUnavailableNotARefusal(t *testing.T) {
	m := migratedWithRoles(t)
	drift, _ := seedAlerts(t, m.owner, 1)
	store, _ := readStore(t, m.readerDSN)
	authStore, err := OpenAuthStore(context.Background(), m.authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(authStore.Close)
	r, err := OpenResolver(context.Background(), m.resolverDSN)
	if err != nil {
		t.Fatalf("OpenResolver: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		Store: store, Prover: newProofScenario(t, proofOptions{}).prover(t),
		AuthStore: authStore, WebAuthn: testWebAuthnConfig, Resolver: r,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)
	cookie := signInTestUser(t, listening.URL, authStore)

	r.Close()
	a := do(t, http.MethodPost, listening.URL+"/api/v1/alert-resolutions/begin",
		mustJSON(t, ResolveRequest{EventIDs: []string{eventIDOf(t, drift[0])}, Reason: "why"}), cookie)
	if a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "nothing was written") {
		t.Errorf("begin against a closed resolver pool: %d: %s", a.status, a.body)
	}
}
