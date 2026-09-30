// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/ledger"
)

// Coverage for EnsureAuthWriterRole's own branches — readonly.go's
// EnsureReadOnlyRole carries the identical shape and this project's own
// convention is to prove each half the same way.

func TestEnsureAuthWriterRoleRefusesABadRoleName(t *testing.T) {
	if err := EnsureAuthWriterRole(context.Background(), "postgres://x", "not a valid role; drop table", "pw"); err == nil {
		t.Fatal("EnsureAuthWriterRole accepted a role name that is not a usable identifier")
	}
}

func TestEnsureAuthWriterRoleRefusesAnUnreachableAdminDSN(t *testing.T) {
	unreachable := "postgres://nobody:nothing@127.0.0.1:1/nonexistent?connect_timeout=1"
	if err := EnsureAuthWriterRole(context.Background(), unreachable, "innsegl_authwriter_probe", "pw"); err == nil {
		t.Fatal("EnsureAuthWriterRole accepted an unreachable admin DSN")
	}
}

// migratedAuthWriterFixture is migratedWithAuth's own body, kept here (not
// reused from it) only because this file needs the container and database
// name migratedWithAuth does not return, to build a SECOND DSN of its own
// against the same database.
func migratedAuthWriterFixture(t *testing.T) (c *pgContainer, database, ownerDSN, authDSN string) {
	t.Helper()
	c, database, ownerDSN = freshDB(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s, err := ledger.Open(ctx, ownerDSN)
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("ledger.Migrate: %v", err)
	}
	if err := EnsureAuthWriterRole(ctx, ownerDSN, AuthWriterRole, authWriterPassword); err != nil {
		t.Fatalf("EnsureAuthWriterRole: %v", err)
	}
	return c, database, ownerDSN, c.dsn(database, AuthWriterRole, authWriterPassword)
}

// The ALTER branch: a second call against a role the first call already
// created. The fixture above's own EnsureAuthWriterRole call is always the
// CREATE branch (a fresh database every time); this is the other half.
func TestEnsureAuthWriterRoleAltersAnExistingRole(t *testing.T) {
	c, database, ownerDSN, _ := migratedAuthWriterFixture(t)

	if err := EnsureAuthWriterRole(context.Background(), ownerDSN, AuthWriterRole, "second-password"); err != nil {
		t.Fatalf("EnsureAuthWriterRole (ALTER, with a password) on an already-provisioned role: %v", err)
	}

	// The password just set above must actually work: connecting as the
	// role with it is the measurement, not the absence of a Go error.
	store, err := OpenAuthStore(context.Background(), c.dsn(database, AuthWriterRole, "second-password"))
	if err != nil {
		t.Fatalf("connecting with the altered password: %v", err)
	}
	store.Close()
}

// exists && password == "": no case in EnsureAuthWriterRole's switch
// matches, and that absence is deliberate ("an empty password leaves the
// role's authentication alone") — proved here by reapplying with no
// password and then reconnecting with the ORIGINAL one.
func TestEnsureAuthWriterRoleLeavesAnExistingPasswordAloneWhenGivenNone(t *testing.T) {
	_, _, ownerDSN, authDSN := migratedAuthWriterFixture(t)

	if err := EnsureAuthWriterRole(context.Background(), ownerDSN, AuthWriterRole, ""); err != nil {
		t.Fatalf("EnsureAuthWriterRole (no password) on an already-provisioned role: %v", err)
	}

	store, err := OpenAuthStore(context.Background(), authDSN)
	if err != nil {
		t.Fatalf("the original password no longer works after an empty-password re-apply: %v", err)
	}
	store.Close()
}
