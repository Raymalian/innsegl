// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ADR-0062: "The credential that answers a WebAuthn ceremony or issues a
// session must never be able to write innsegl.events or any table
// internal/api/readonly.go's AssertReadOnly already protects." These cases
// ask the server, never the Go source.

// AUTH-003-support: the auth-writer role is refused every ledger write by the
// Postgres server itself, the same way API-002 proves it for the reader.
func TestAuthWriterRoleIsRefusedEveryLedgerWriteByThePostgresServer(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, authDSN)
	if err != nil {
		t.Fatalf("connect as %s: %v", AuthWriterRole, err)
	}
	defer func() { _ = conn.Close(ctx) }()

	report, err := AssertCannotWriteLedger(ctx, conn)
	if err != nil {
		t.Fatalf("AssertCannotWriteLedger: %v", err)
	}
	if report.Writable() {
		t.Fatalf("the auth-writer role can write the ledger schema: %+v", report.Probes)
	}
}

// AUTH-003-support: the same credential CAN write its own schema — a
// negative-only proof would not distinguish "denied everything" from "denied
// nothing in particular".
func TestAuthWriterRoleCanWriteItsOwnSchema(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := OpenAuthStore(ctx, authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(store.Close)

	if err := store.CreateUser(ctx, "u-1", "Dev Operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

// Migration 0009's own additions (#445): the auth-writer role's blanket
// "ALL TABLES IN SCHEMA innsegl_auth" grant (authwriter.sql) is applied
// AFTER migrations run (apiharness_test.go's migratedWithAuth), so it
// already covers a table 0009 adds — this proves that holds for
// recovery_codes, passkeys.name and sessions.passkey_id, the same way
// TestAuthWriterRoleCanWriteItsOwnSchema proves it for 0008's own tables.
func TestAuthWriterRoleCanWriteTheAccountsAdditions(t *testing.T) {
	_, _, _, authDSN := migratedWithAuth(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store, err := OpenAuthStore(ctx, authDSN)
	if err != nil {
		t.Fatalf("OpenAuthStore: %v", err)
	}
	t.Cleanup(store.Close)

	if err := store.CreateUser(ctx, "u-accounts", "Accounts Operator"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cred := webauthn.Credential{ID: []byte("accounts-grant-check"), AttestationFormat: "none"}
	if _, err := store.AddPasskey(ctx, "u-accounts", "named passkey", cred); err != nil {
		t.Fatalf("AddPasskey with a name: %v", err)
	}
	passkeyID := credentialIDString(cred.ID)
	if _, _, err := store.CreateSession(ctx, "u-accounts", passkeyID, time.Hour); err != nil {
		t.Fatalf("CreateSession with a passkey_id: %v", err)
	}
	if _, err := store.MintRecoveryCodes(ctx, "u-accounts"); err != nil {
		t.Fatalf("MintRecoveryCodes: %v", err)
	}
	if n, err := store.RecoveryCodesRemaining(ctx, "u-accounts"); err != nil || n != 10 {
		t.Fatalf("RecoveryCodesRemaining: n=%d err=%v, want 10, nil", n, err)
	}
}

// AssertCannotWriteLedger itself refuses a credential that CAN write the
// ledger — the owner — proving the assertion is a real measurement and not a
// tautology that always reports "fine".
func TestAssertCannotWriteLedgerCatchesAWritingCredential(t *testing.T) {
	_, ownerDSN, _, _ := migratedWithAuth(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connect as owner: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	_, err = AssertCannotWriteLedger(ctx, conn)
	if !errors.Is(err, ErrWritable) {
		t.Fatalf("AssertCannotWriteLedger accepted the owner credential; want an error "+
			"wrapping ErrWritable, got %v", err)
	}
}
