// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// The auth-writer credential, and the proof that it cannot touch the ledger.
//
// ADR-0062 draws this split for RM-260/RM-261: the API process gains a
// SECOND database role, scoped to the new innsegl_auth schema only, so that
// answering a WebAuthn ceremony or issuing a session never needs — and never
// gets — a grant on anything readonly.go's AssertReadOnly already protects.
// This file is authwriter.sql's Go half, mirroring readonly.go's own shape:
// EnsureAuthWriterRole provisions, AssertCannotWriteLedger measures.

// AuthWriterRole is the Postgres role the auth half of the API connects as. A
// default, not a protected string, exactly as ReadOnlyRole is.
const AuthWriterRole = "innsegl_authwriter"

//go:embed authwriter.sql
var authWriterGrants string

// EnsureAuthWriterRole creates the role if it is absent and applies
// authwriter.sql to it, using an ADMINISTRATIVE dsn — operator tooling, in
// readonly.go's EnsureReadOnlyRole's own words, "deliberately not something
// the API can do".
func EnsureAuthWriterRole(ctx context.Context, adminDSN, role, password string) error {
	if !roleNamePattern.MatchString(role) {
		return fmt.Errorf("api: %q is not a usable role name", role)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("api: connecting as the administrator: %w", err)
	}
	defer func() { _ = admin.Close(ctx) }()

	var database string
	if derr := admin.QueryRow(ctx, `SELECT current_database()`).Scan(&database); derr != nil {
		return fmt.Errorf("api: reading the current database: %w", derr)
	}

	var exists bool
	if lerr := admin.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); lerr != nil {
		return fmt.Errorf("api: looking up the role %s: %w", role, lerr)
	}
	ident := pgx.Identifier{role}.Sanitize()
	switch {
	case !exists && password != "":
		_, err = admin.Exec(ctx, "CREATE ROLE "+ident+" LOGIN PASSWORD "+quoteLiteral(password))
	case !exists:
		_, err = admin.Exec(ctx, "CREATE ROLE "+ident+" LOGIN")
	case password != "":
		_, err = admin.Exec(ctx, "ALTER ROLE "+ident+" LOGIN PASSWORD "+quoteLiteral(password))
	}
	if err != nil {
		return fmt.Errorf("api: provisioning the role %s: %w", role, err)
	}

	grants := fmt.Sprintf(authWriterGrants, ident, pgx.Identifier{database}.Sanitize())
	if _, err := admin.Exec(ctx, grants); err != nil {
		return fmt.Errorf("api: applying the auth-writer grants to %s: %w", role, err)
	}
	return nil
}

// AssertCannotWriteLedger asks the server whether the auth-writer credential
// — which legitimately writes innsegl_auth.* — can write anything in the
// ledger schema AssertReadOnly already protects. It reuses AssertReadOnly's
// own write probes unchanged: the question ("can this role write the tables
// writeProbes names?") is identical to the one the read-only role is asked,
// only the credential differs.
func AssertCannotWriteLedger(ctx context.Context, c conn) (ReadOnlyReport, error) {
	report, err := AssertReadOnly(ctx, c)
	if err != nil {
		return report, fmt.Errorf("api: the auth-writer credential can write the ledger "+
			"schema ADR-0062 requires it stay out of: %w", err)
	}
	return report, nil
}
