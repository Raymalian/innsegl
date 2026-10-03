// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RM-330 (#506), ADR-0044's 2026-10-03 amendment — the resolver credential.
//
// The dashboard may now resolve alerts, so the API process holds a THIRD
// database credential. It must be able to insert an alert resolution and do
// nothing else: no write to any table AssertReadOnly protects, no update or
// delete of a resolution once written, and no read of innsegl_auth. These
// cases ask the server, as every role case in this package does.

func resolverPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestRM330TheResolverRoleCanInsertAResolutionAndNothingElse(t *testing.T) {
	m := migratedWithRoles(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	report, err := AssertResolverScope(ctx, resolverPool(t, m.resolverDSN))
	if err != nil {
		t.Fatalf("AssertResolverScope on the provisioned role: %v", err)
	}
	if report.Ledger.Writable() {
		t.Errorf("the resolver role can write the ledger: %+v", report.Ledger)
	}
	allowed := map[string]bool{}
	for _, p := range report.Probes {
		allowed[p.Name] = p.Allowed
	}
	if !allowed[probeInsertResolution] {
		t.Errorf("the resolver role cannot insert a resolution: %+v", report.Probes)
	}
	for _, name := range []string{probeUpdateResolution, probeDeleteResolution, probeReadAuth} {
		if allowed[name] {
			t.Errorf("the resolver role is allowed to %s", name)
		}
	}
}

func TestRM330AssertResolverScopeRefusesTheOwnerAndTheReader(t *testing.T) {
	m := migratedWithRoles(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := AssertResolverScope(ctx, resolverPool(t, m.ownerDSN)); !errors.Is(err, ErrWritable) {
		t.Errorf("AssertResolverScope(owner) = %v, want ErrWritable", err)
	}
	if _, err := AssertResolverScope(ctx, resolverPool(t, m.readerDSN)); !errors.Is(err, ErrResolverCannotResolve) {
		t.Errorf("AssertResolverScope(reader) = %v, want ErrResolverCannotResolve", err)
	}
	// The auth writer can read innsegl_auth and cannot insert a resolution:
	// refused for the second reason before the first.
	if _, err := AssertResolverScope(ctx, resolverPool(t, m.authDSN)); err == nil {
		t.Error("AssertResolverScope accepted the auth-writer credential")
	}
}

func TestRM330OpenResolver(t *testing.T) {
	m := migratedWithRoles(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	r, err := OpenResolver(ctx, m.resolverDSN)
	if err != nil {
		t.Fatalf("OpenResolver(resolver role): %v", err)
	}
	if r.Scope().Ledger.Role != ResolverRole {
		t.Errorf("Scope().Ledger.Role = %q, want %q", r.Scope().Ledger.Role, ResolverRole)
	}
	r.Close()

	if _, err := OpenResolver(ctx, m.ownerDSN); !errors.Is(err, ErrWritable) {
		t.Errorf("OpenResolver(owner) = %v, want ErrWritable", err)
	}
	if _, err := OpenResolver(ctx, "postgres://x:y@127.0.0.1:1/z?connect_timeout=1"); err == nil {
		t.Error("OpenResolver on an unreachable DSN succeeded")
	}
	if _, err := OpenResolver(ctx, "::not a dsn::"); err == nil {
		t.Error("OpenResolver on a malformed DSN succeeded")
	}
}

func TestRM330EnsureResolverRoleRefusals(t *testing.T) {
	if err := EnsureResolverRole(context.Background(), "postgres://x", "not a role; drop table", "pw"); err == nil {
		t.Error("EnsureResolverRole accepted an unusable role name")
	}
	m := migratedWithRoles(t)
	// Re-applying to an existing role, with and without a password, is the
	// db-init re-run case and must succeed.
	if err := EnsureResolverRole(context.Background(), m.ownerDSN, ResolverRole, "second-password"); err != nil {
		t.Errorf("EnsureResolverRole (ALTER with a password): %v", err)
	}
	if err := EnsureResolverRole(context.Background(), m.ownerDSN, ResolverRole, ""); err != nil {
		t.Errorf("EnsureResolverRole (existing role, no password): %v", err)
	}
	if err := EnsureResolverRole(context.Background(), m.ownerDSN, "innsegl_resolver_nopw", ""); err != nil {
		t.Errorf("EnsureResolverRole (new role, no password): %v", err)
	}
}
