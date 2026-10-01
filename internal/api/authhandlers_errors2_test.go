// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A second file of handler-level error coverage — the handler's OWN "if
// !decodeAuthRequest(...)" and "if err != nil { ... could not read the
// saved ceremony }" branches, which are distinct call sites from
// decodeAuthRequest's and json.Unmarshal's own unit-level branches already
// covered in authhandlers_errors_test.go and authmisc_errors_test.go.

func TestHandleEnrolBeginRefusesAMalformedBody(t *testing.T) {
	srv, _, _ := testServerConfigured(t)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/begin", "{not json")
	if a.status != http.StatusBadRequest {
		t.Fatalf("enrol/begin with a malformed body returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

func TestHandleEnrolFinishRefusesAMalformedBody(t *testing.T) {
	srv, _, _ := testServerConfigured(t)
	a := do(t, http.MethodPost, srv.URL+"/api/v1/auth/enrol/finish", "{not json")
	if a.status != http.StatusBadRequest {
		t.Fatalf("enrol/finish with a malformed body returned %d, want %d: %s",
			a.status, http.StatusBadRequest, a.body)
	}
}

// ceremonyCorruptionHarness is its own, self-contained server (not
// testServerConfigured/testAuthStore, neither of which hands back the
// OWNER credential the corruption below needs) so this file can reach the
// one database its auth schema actually lives in directly.
type ceremonyCorruptionHarness struct {
	srv      *httptest.Server
	ownerDSN string
}

func newCeremonyCorruptionHarness(t *testing.T) ceremonyCorruptionHarness {
	t.Helper()
	_, ownerDSN, readerDSN, authDSN := migratedWithAuth(t)
	store, _ := readStore(t, readerDSN)
	authStore, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(authStore.Close)

	scenario := newProofScenario(t, proofOptions{})
	handler, err := NewServer(ServerConfig{
		Store: store, Prover: scenario.prover(t),
		AuthStore: authStore, WebAuthn: testWebAuthnConfig,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(handler)
	t.Cleanup(listening.Close)
	return ceremonyCorruptionHarness{srv: listening, ownerDSN: ownerDSN}
}

// corruptSessionData connects with the migration OWNER credential (never
// innsegl_authwriter in production) and overwrites one ceremony's
// session_data with valid JSON that is not webauthn.SessionData's shape —
// "expires" is a JSON number where the library's own struct expects an
// RFC 3339 timestamp, so json.Unmarshal fails on a type mismatch rather
// than silently zero-filling the field.
func (h ceremonyCorruptionHarness) corruptSessionData(t *testing.T, ceremonyID string) {
	t.Helper()
	ctx := context.Background()
	owner, err := pgx.Connect(ctx, h.ownerDSN)
	if err != nil {
		t.Fatalf("connecting as owner to corrupt a ceremony: %v", err)
	}
	defer func() { _ = owner.Close(ctx) }()
	if _, err := owner.Exec(ctx,
		`UPDATE innsegl_auth.webauthn_ceremonies SET session_data = '{"expires": 12345}'::jsonb
		 WHERE ceremony_id = $1`, ceremonyID); err != nil {
		t.Fatalf("corrupting the ceremony row: %v", err)
	}
}

func TestHandleEnrolFinishReportsAnUnreadableCeremony(t *testing.T) {
	h := newCeremonyCorruptionHarness(t)

	code, err := mintCodeFor(h)
	if err != nil {
		t.Fatalf("minting an enrolment code: %v", err)
	}
	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/enrol/begin", enrolBeginBody(t, "Operator", code))
	if begin.status != http.StatusOK {
		t.Fatalf("enrol/begin: %d: %s", begin.status, begin.body)
	}
	var creation ceremonyResponse
	if jerr := json.Unmarshal(begin.body, &creation); jerr != nil {
		t.Fatalf("decoding enrol/begin: %v", jerr)
	}

	h.corruptSessionData(t, creation.CeremonyID)

	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": creation.CeremonyID,
		"credential":  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	finish := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/enrol/finish", string(finishBody))
	if finish.status != http.StatusInternalServerError {
		t.Fatalf("enrol/finish with an unreadable ceremony returned %d, want %d: %s",
			finish.status, http.StatusInternalServerError, finish.body)
	}
}

func TestHandleLoginFinishReportsAnUnreadableCeremony(t *testing.T) {
	h := newCeremonyCorruptionHarness(t)

	begin := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login/begin", "{}")
	if begin.status != http.StatusOK {
		t.Fatalf("login/begin: %d: %s", begin.status, begin.body)
	}
	var assertion loginCeremonyResponse
	if jerr := json.Unmarshal(begin.body, &assertion); jerr != nil {
		t.Fatalf("decoding login/begin: %v", jerr)
	}

	h.corruptSessionData(t, assertion.CeremonyID)

	finishBody, err := json.Marshal(map[string]any{
		"ceremony_id": assertion.CeremonyID,
		"credential":  json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	finish := do(t, http.MethodPost, h.srv.URL+"/api/v1/auth/login/finish", string(finishBody))
	if finish.status != http.StatusInternalServerError {
		t.Fatalf("login/finish with an unreadable ceremony returned %d, want %d: %s",
			finish.status, http.StatusInternalServerError, finish.body)
	}
}

// mintCodeFor connects to the harness's own auth database with the OWNER
// credential and mints a one-time code the long way (an INSERT matching
// AuthStore.CreateEnrolmentCode's own SQL) — the harness already closes its
// AuthStore over its full lifetime for the handler to use, and opening a
// second one just to mint one code would be the same connection pool twice
// over for one INSERT.
func mintCodeFor(h ceremonyCorruptionHarness) (string, error) {
	ctx := context.Background()
	owner, err := pgx.Connect(ctx, h.ownerDSN)
	if err != nil {
		return "", err
	}
	defer func() { _ = owner.Close(ctx) }()

	raw := "test-only-enrolment-code-0123456789abcdef"
	sum := hashToken(raw)
	if _, err := owner.Exec(ctx,
		`INSERT INTO innsegl_auth.enrolment_codes (code_hash, expires_at)
		 VALUES ($1, clock_timestamp() + interval '5 minutes')`, sum); err != nil {
		return "", err
	}
	return raw, nil
}
