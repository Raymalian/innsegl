// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
