// SPDX-License-Identifier: Apache-2.0

package ledgerdb

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"innsegl.dev/innsegl/test/deploy/deploytest"
)

// OPS-212 (RM-356, #604) — the backup role cannot create databases.
//
// The backup proves a dump restores by restoring it into a throwaway Postgres
// of its own (scripts/backup-ledger.sh), so the ledger server owes the backup's
// credential nothing beyond reading the ledger. db-init.sh provisions it from
// readonly.sql, whose last line is NOCREATEDB, and runs on every `make update`:
// an existing deployment whose role still carries the old CREATEDB loses it at
// its next update, and a second run changes nothing. verify-backup-role.sh,
// which db-init.sh runs, refuses a role that has it back.
func TestOPS212TheBackupRoleCannotCreateDatabases(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg := ledgerForTest(ctx, t, "OPS-212", "the backup credential leaves the core "+
		"every night, so what it may do on the ledger server is measured, not assumed")
	provision(ctx, t, pg)
	if backupCanCreateDB(ctx, t, pg) {
		t.Fatalf("a fresh db-init left %s with CREATEDB", deploytest.BackupRole)
	}

	// An existing deployment: the role as the previous db-init left it.
	if err := pg.PsqlAsOwner(ctx, "ALTER ROLE "+deploytest.BackupRole+" CREATEDB"); err != nil {
		t.Fatalf("giving the role its old CREATEDB: %v", err)
	}
	out, err := pg.RunInit(ctx, "verify-backup-role.sh")
	if err == nil {
		t.Fatalf("verify-backup-role.sh passed a role that can create databases:\n%s", out)
	}
	if !strings.Contains(out, "create a database") {
		t.Errorf("verify-backup-role.sh did not name CREATEDB:\n%s", out)
	}

	// The update: db-init runs again, twice, and the second run is a no-op.
	for run := 1; run <= 2; run++ {
		out, err := pg.RunInit(ctx, "db-init.sh")
		if err != nil {
			t.Fatalf("db-init.sh run %d on an existing ledger failed: %v\n%s", run, err, out)
		}
		if backupCanCreateDB(ctx, t, pg) {
			t.Fatalf("db-init.sh run %d left %s with CREATEDB:\n%s", run, deploytest.BackupRole, out)
		}
	}
}

func backupCanCreateDB(ctx context.Context, t *testing.T, pg *deploytest.LedgerContainer) bool {
	t.Helper()
	conn, err := pgx.Connect(ctx, pg.OwnerDSN())
	if err != nil {
		t.Fatalf("connecting as the owner: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var createdb, super bool
	if err := conn.QueryRow(ctx,
		"SELECT rolcreatedb, rolsuper FROM pg_roles WHERE rolname = $1",
		deploytest.BackupRole).Scan(&createdb, &super); err != nil {
		t.Fatalf("reading %s from pg_roles: %v", deploytest.BackupRole, err)
	}
	if super {
		t.Fatalf("%s is a superuser", deploytest.BackupRole)
	}
	return createdb
}
