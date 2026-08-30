// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TC-API read-only enforcement.
//
// FD §7: the dashboard "holds no credentials capable of writing anywhere", and
// #48 spells out what that has to mean — "enforced with a read-only database
// role, not merely by the absence of write code. The role is the enforcement;
// the missing code is a convention."
//
// So these cases do not read the Go source for the absence of INSERT. They ask
// the SERVER what the credential can do, and require every answer to be a
// refusal.

// API-001 — Open refuses a credential that can write.
func TestAPI001OpenRefusesACredentialThatCanWrite(t *testing.T) {
	_, ownerDSN, readerDSN := migrated(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The owner credential is exactly the credential this API must never hold.
	store, err := Open(ctx, ownerDSN)
	if err == nil {
		store.Close()
		t.Fatalf("Open accepted the owner credential; a read-only API that can be " +
			"handed a writing credential enforces nothing (FD §7, P6)")
	}
	if !errors.Is(err, ErrWritable) {
		t.Fatalf("Open refused the owner credential with %v, want an error wrapping ErrWritable", err)
	}
	// The refusal has to name what the credential could do, or an operator
	// cannot act on it.
	if !strings.Contains(err.Error(), "innsegl.events") {
		t.Errorf("the refusal does not name a write the credential was allowed: %v", err)
	}

	// The reader credential is accepted.
	ro, err := Open(ctx, readerDSN)
	if err != nil {
		t.Fatalf("Open refused the read-only credential: %v", err)
	}
	t.Cleanup(ro.Close)
}

// API-002 — the provisioned role is refused every write by the server itself.
//
// Each probe runs on a raw connection with the transaction explicitly set READ
// WRITE, so that what refuses the write is the GRANT and not the
// default_transaction_read_only setting a session can turn off for itself. A
// read-only posture that a `SET` can lift is not a posture.
func TestAPI002TheReadOnlyRoleIsRefusedEveryWriteByThePostgresServer(t *testing.T) {
	_, _, readerDSN := migrated(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, readerDSN)
	if err != nil {
		t.Fatalf("connect as %s: %v", ReadOnlyRole, err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if len(writeProbes()) < 6 {
		t.Fatalf("only %d write probes; the credential must be shown unable to write "+
			"to any of the three tables, to create one of its own, or to create a "+
			"schema to put one in", len(writeProbes()))
	}

	for _, p := range writeProbes() {
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("%s: begin: %v", p.Name, err)
		}
		if _, err := tx.Exec(ctx, "SET TRANSACTION READ WRITE"); err != nil {
			t.Fatalf("%s: the probe could not even ask for a writable transaction: %v",
				p.Name, err)
		}
		_, err = tx.Exec(ctx, p.SQL)
		_ = tx.Rollback(ctx)

		if err == nil {
			t.Errorf("%s: the read-only role was ALLOWED to %s. FD §7 requires a "+
				"credential incapable of writing anywhere", p.Name, p.Name)
			continue
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) {
			t.Errorf("%s: refused with a non-Postgres error %v; the refusal must come "+
				"from the server", p.Name, err)
			continue
		}
		if !isPrivilegeRefusal(pgErr.Code) {
			t.Errorf("%s: refused with SQLSTATE %s (%s); want a privilege refusal. "+
				"A write that fails for some other reason today is a write that "+
				"succeeds tomorrow", p.Name, pgErr.Code, pgErr.Message)
		}
	}

	// A credential that cannot read either is broken, not read-only: the
	// refusals above have to be about privilege and not about connectivity.
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM innsegl.events").Scan(&n); err != nil {
		t.Fatalf("the read-only role cannot SELECT: %v", err)
	}

	// A superuser bypasses every ACL above, so the probes would prove nothing.
	var super string
	if err := conn.QueryRow(ctx, "SELECT current_setting('is_superuser')").Scan(&super); err != nil {
		t.Fatalf("reading is_superuser: %v", err)
	}
	if super != "off" {
		t.Fatalf("the read-only role is a superuser (is_superuser=%s); ACLs do not "+
			"bind it and nothing above was proven", super)
	}
}

// AssertReadOnly is the gate Open runs. It must convict a writing credential
// and clear a reading one, against the real server both times.
func TestAssertReadOnlyConvictsTheOwnerAndClearsTheReader(t *testing.T) {
	_, ownerDSN, readerDSN := migrated(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	owner, err := pgx.Connect(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("connect as owner: %v", err)
	}
	defer func() { _ = owner.Close(ctx) }()

	report, err := AssertReadOnly(ctx, owner)
	if err == nil {
		t.Fatalf("AssertReadOnly cleared the owner credential: %+v", report)
	}
	if !errors.Is(err, ErrWritable) {
		t.Fatalf("AssertReadOnly refused the owner with %v, want ErrWritable", err)
	}
	allowed := 0
	for _, r := range report.Probes {
		if r.Allowed {
			allowed++
		}
	}
	if allowed == 0 {
		t.Errorf("the report records no allowed write, but the owner can write: %+v", report.Probes)
	}

	reader, err := pgx.Connect(ctx, readerDSN)
	if err != nil {
		t.Fatalf("connect as reader: %v", err)
	}
	defer func() { _ = reader.Close(ctx) }()

	report, err = AssertReadOnly(ctx, reader)
	if err != nil {
		t.Fatalf("AssertReadOnly refused the read-only role: %v (%+v)", err, report.Probes)
	}
	if len(report.Probes) != len(writeProbes()) {
		t.Errorf("the report covers %d probes, %d were attempted",
			len(report.Probes), len(writeProbes()))
	}
	for _, r := range report.Probes {
		if r.Allowed {
			t.Errorf("%s: recorded as allowed on the read-only role", r.Name)
		}
		if r.SQLState == "" {
			t.Errorf("%s: no SQLSTATE recorded; the report is the evidence an "+
				"operator reads", r.Name)
		}
	}
	if report.Superuser {
		t.Error("the read-only role is reported as a superuser")
	}
}
