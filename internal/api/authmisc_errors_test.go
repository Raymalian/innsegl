// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

// Remaining error/refusal paths that do not fit authstore_errors_test.go's
// closed-pool technique or authhandlers_errors_test.go's HTTP-level one.

// ---------------------------------------------------------------------------
// newWebAuthn — pure validation, no Postgres needed.
// ---------------------------------------------------------------------------

func TestNewWebAuthnRefusesAnEmptyRPID(t *testing.T) {
	if _, err := newWebAuthn(WebAuthnConfig{RPOrigin: "http://localhost:8082"}); err == nil {
		t.Fatal("newWebAuthn accepted an empty RP ID")
	}
}

func TestNewWebAuthnRefusesAnEmptyRPOrigin(t *testing.T) {
	if _, err := newWebAuthn(WebAuthnConfig{RPID: "localhost"}); err == nil {
		t.Fatal("newWebAuthn accepted an empty RP origin")
	}
}

func TestNewWebAuthnDefaultsTheDisplayName(t *testing.T) {
	w, err := newWebAuthn(WebAuthnConfig{RPID: "localhost", RPOrigin: "http://localhost:8082"})
	if err != nil {
		t.Fatalf("newWebAuthn: %v", err)
	}
	if w.Config.RPDisplayName != "Innsegl" {
		t.Errorf("RPDisplayName = %q, want the default %q", w.Config.RPDisplayName, "Innsegl")
	}
}

// ---------------------------------------------------------------------------
// ManagedSettingsPathFromEnv — both branches.
// ---------------------------------------------------------------------------

func TestManagedSettingsPathFromEnvUsesTheVariableWhenSet(t *testing.T) {
	t.Setenv(EnvManagedSettingsFile, "/custom/managed-settings.json")
	if got := ManagedSettingsPathFromEnv(); got != "/custom/managed-settings.json" {
		t.Errorf("ManagedSettingsPathFromEnv() = %q, want the env value", got)
	}
}

func TestManagedSettingsPathFromEnvFallsBackToTheDefault(t *testing.T) {
	t.Setenv(EnvManagedSettingsFile, "")
	if got, want := ManagedSettingsPathFromEnv(), DefaultManagedSettingsPath(runtime.GOOS); got != want {
		t.Errorf("ManagedSettingsPathFromEnv() = %q, want the per-OS default %q", got, want)
	}
}

// A failed crypto/rand.Reader was tried here and removed: as of Go 1.27
// (see https://go.dev/issue/66821), crypto/rand.Read treats a Reader
// failure as UNRECOVERABLE and calls runtime fatal — it does not return an
// error at all. newRandomID's own `if err != nil` branch (and therefore
// NewUserID/CreateSession/CreateEnrolmentCode/SaveCeremony's share of it)
// is genuinely unreachable on this toolchain: there is no way to provoke it
// without crashing the test binary, which is a finding about the Go
// runtime's own hardening, not a gap this file can honestly close.

// ---------------------------------------------------------------------------
// scanPasskeyUser's decode failure — a row whose stored credential is not
// the JSON AddPasskey itself would ever write. Provoked honestly: connect
// with the OWNER credential (never innsegl_authwriter in production) and
// corrupt the one row directly, exactly the "a hand-widened role" scenario
// this schema otherwise never produces.
// ---------------------------------------------------------------------------

func TestPasskeysByUserReportsAStoredCredentialItCannotDecode(t *testing.T) {
	_, ownerDSN, _, authDSN := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	if cerr := store.CreateUser(ctx, "u-corrupt", "Corrupt"); cerr != nil {
		t.Fatalf("CreateUser: %v", cerr)
	}
	if aerr := store.AddPasskey(ctx, "u-corrupt", webauthnTestCredential("corrupt-me")); aerr != nil {
		t.Fatalf("AddPasskey: %v", aerr)
	}

	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connecting as owner to corrupt a row: %v", err)
	}
	defer func() { _ = owner.Close(ctx) }()
	// Valid JSON (jsonb itself validates syntax on write, so anything
	// syntactically invalid is refused before it ever reaches this table),
	// but the wrong SHAPE: webauthn.Credential.ID is []byte, which
	// encoding/json expects as a base64 string, and a JSON number is not one.
	if _, err := owner.Exec(ctx,
		`UPDATE innsegl_auth.passkeys SET credential = '{"id": 12345}'::jsonb WHERE user_id = $1`,
		"u-corrupt"); err != nil {
		t.Fatalf("corrupting the row: %v", err)
	}

	if _, err := store.PasskeysByUser(ctx, "u-corrupt"); err == nil {
		t.Fatal("PasskeysByUser decoded a row that is not valid JSON")
	}
}

// UpdatePasskey's own not-found branch — RowsAffected()==0 is not a DB
// error, it is a distinct, named sentinel.
func TestUpdatePasskeyReportsNotFoundForAnUnknownCredential(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	defer store.Close()

	err = store.UpdatePasskey(context.Background(), webauthnTestCredential("never-added"))
	if !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("UpdatePasskey on an unknown credential returned %v, want ErrPasskeyNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// issueSession's own CreateSession-error branch — called directly (it is
// unexported, same package), since isolating a DB failure on the SPECIFIC
// last write of an otherwise-successful ceremony is not reachable by
// closing the whole store before the request, the way the earlier,
// first-write branches are.
// ---------------------------------------------------------------------------

func TestIssueSessionReportsACreateSessionDatabaseError(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)
	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	store.Close()

	s := &Server{
		authStore:       store,
		webAuthnConfig:  WebAuthnConfig{RPOrigin: "http://localhost:8082"},
		sessionLifetime: time.Hour,
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	s.issueSession(rec, req, "user-1", "Operator")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("issueSession against a closed store answered %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func webauthnTestCredential(credentialID string) webauthn.Credential {
	return webauthn.Credential{ID: []byte(credentialID), AttestationFormat: "none"}
}
