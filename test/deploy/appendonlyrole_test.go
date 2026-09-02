// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/ledger"
)

// ---------------------------------------------------------------------------
// OPS-009 (PROPOSED for doc 07's TC-OPS) — the append-only database role is
// provisioned by the shipped deployment, and then MEASURED rather than
// asserted.
//
// doc 05 §1: the MCP runs under a role that can append and cannot delete.
// Before #109 nothing created one; `innsegl serve` printed DATABASE ROLE IS
// OVER-PRIVILEGED and started anyway, so the first thing an adopter met was a
// message saying the system's own database privileges were wrong.
//
// internal/api/readonly.sql is the model and its lesson is the important part:
// it does not merely grant less, it provisions the role and then ASKS THE
// SERVER what the credential can actually do, refusing to hand back a
// connection if the answer is "write". A role that is asserted rather than
// verified is exactly what this issue is about — a later GRANT by an operator
// who wanted to "just fix one thing" is invisible to any amount of review.
//
// MEASURED, on postgres:16, and it is the fact the whole check rests on:
//
//	role      statement                        SQLSTATE
//	appender  UPDATE innsegl.events            42501  permission denied (the ACL)
//	appender  DELETE FROM innsegl.events       42501  permission denied (the ACL)
//	appender  TRUNCATE innsegl.events          42501  permission denied (the ACL)
//	owner     UPDATE innsegl.events            IN001  the append-only trigger
//	owner     DELETE FROM innsegl.events       IN001  the append-only trigger
//	owner     TRUNCATE innsegl.events          IN001  the append-only trigger
//
// Both roles are refused; only one of them is refused BY PRIVILEGE. A check
// that asked "did the statement fail?" would pass the database owner — the
// very credential #109 is about. So the check classifies by SQLSTATE, and
// anything that is not a privilege refusal counts as allowed.
// ---------------------------------------------------------------------------

// The two SQLSTATEs that are a refusal BY PRIVILEGE, spelled as
// internal/api/readonly.go spells them.
const (
	sqlStateInsufficientPrivilege = "42501"
	sqlStateReadOnlyTransaction   = "25006"
)

func isPrivilegeRefusal(code string) bool {
	return code == sqlStateInsufficientPrivilege || code == sqlStateReadOnlyTransaction
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// A well-formed event at chain position 1. It is refused by the chain-link
// trigger (IN002) because its prev_event_hash is not the genesis constant —
// which is the point: reaching a trigger means the ACL let the statement
// through, and the ACL is what is being measured.
const probeInsertEvent = `INSERT INTO innsegl.events
	(chain_position, event_id, event_hash, prev_event_hash, event_type,
	 source, ts, canonical)
 VALUES (1, '00000000-0000-7000-8000-000000000000',
	 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
	 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
	 'run_registered', 'mcp', now(), '\x7b7d'::bytea)`

// appendOnlyExpectations is what doc 05 §1's role must and must not be able to
// do. `allowed` is about the ACL and nothing else.
var appendOnlyExpectations = []struct {
	name    string
	sql     string
	allowed bool
	why     string
}{
	{"append to the chain", probeInsertEvent, true,
		"every MCP tool but get_credential appends; I3 admits no action without a record"},
	{"read the chain", `SELECT count(*) FROM innsegl.events`, true,
		"the MCP reads its own head to compute prev_event_hash"},
	{"read the chain identity", `SELECT chain_id FROM innsegl.chain`, true,
		"ledger.Open checks the genesis constant before it appends anything"},
	{"take an idempotency claim", `INSERT INTO innsegl.idempotency
		(idempotency_key, tool, request_digest, status, lease_expires_at)
	 VALUES ('deploy-probe', 'probe',
		 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
		 'in_progress', now())`, true,
		"IP §6.6's replay record is a claim taken and later completed"},
	{"complete an idempotency claim",
		`UPDATE innsegl.idempotency SET status = 'completed' WHERE idempotency_key = 'deploy-probe'`, true,
		"the same row transitions in_progress -> completed; without UPDATE the MCP " +
			"could take a claim it could never settle"},

	{"update the chain", `UPDATE innsegl.events SET run_id = 'x'`, false,
		"I4: no mutation. The trigger refuses this for the owner too — the ACL is " +
			"what makes it refused for a REASON an operator cannot switch off"},
	{"delete from the chain", `DELETE FROM innsegl.events WHERE false`, false, "I4: no deletion"},
	{"truncate the chain", `TRUNCATE innsegl.events`, false, "I4: no deletion"},
	{"lock the chain for update", `SELECT chain_position FROM innsegl.events FOR UPDATE`, false,
		"the privilege UPDATE needs, taken without an UPDATE statement"},
	{"update the chain identity", `UPDATE innsegl.chain SET chain_id = gen_random_uuid()`, false,
		"the chain's own identity is written once, by migration 0001"},
	{"delete the chain identity", `DELETE FROM innsegl.chain WHERE true`, false,
		"a chain with no genesis row is a chain ledger.Open refuses to walk"},
	{"truncate the idempotency store", `TRUNCATE innsegl.idempotency`, false,
		"migration 0002 refuses TRUNCATE with a trigger; the role must not have the " +
			"privilege either, or the refusal is one ALTER TABLE ... DISABLE away"},
	{"create a table in schema innsegl", `CREATE TABLE innsegl.deploy_probe (x int)`, false,
		"a role with CREATE anywhere is a role that can write; readonly.go's probe set " +
			"makes the same point and it is as true here"},
	{"create a table in schema public", `CREATE TABLE public.deploy_probe (x int)`, false,
		"CREATE on public was granted to PUBLIC before Postgres 15 and is still " +
			"granted on the DATABASE, so it has to be revoked rather than assumed"},
	{"create a schema of its own", `CREATE SCHEMA deploy_probe`, false,
		"somewhere to put a table in"},
}

func TestOPS009TheAppendOnlyRoleIsProvisionedAndProven(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg, err := startLedger(ctx, t)
	skip, failure := startupOutcome(err)
	if pg != nil {
		defer pg.stop()
	}
	switch containerRequirement(pg != nil, skip, failure) {
	case failTest:
		t.Fatalf("the ledger's Postgres did not start on a machine that has Docker: %s\n\n"+
			"This is a FAILURE and not a skip (#101). doc 05 §1's append-only role is a "+
			"security control, and reporting a broken dependency as a skip exits zero "+
			"while nothing measured it.", failure)
	case skipTest:
		t.Skipf("skipping OPS-009: %s. The append-only role is measured against a real "+
			"Postgres — a mocked ACL proves nothing about what a GRANT actually "+
			"permits. Start Docker and re-run.", skip)
	case proceed:
	}

	root := repoRoot(t)
	if stageErr := pg.copyDeployScripts(ctx, root); stageErr != nil {
		t.Fatalf("staging the shipped deploy scripts: %v", stageErr)
	}

	// ---- provisioning, by the shipped script and nothing else --------------
	out, initErr := pg.runInit(ctx, "db-init.sh")
	t.Logf("--- deploy/compose/innsegl/db-init.sh ---\n%s", out)
	if initErr != nil {
		t.Fatalf("db-init.sh failed: %v", initErr)
	}

	// ---- the measurement ---------------------------------------------------
	conn, connErr := pgx.Connect(ctx, pg.appenderDSN())
	if connErr != nil {
		t.Fatalf("the append-only credential could not connect at all: %v", connErr)
	}
	defer func() { discardRollback(conn.Close(ctx)) }()

	var role, superuser string
	if idErr := conn.QueryRow(ctx,
		`SELECT current_user, current_setting('is_superuser')`).Scan(&role, &superuser); idErr != nil {
		t.Fatalf("reading the session's own identity: %v", idErr)
	}
	if role != appenderRole {
		t.Errorf("connected as %q, wanted %q", role, appenderRole)
	}
	if superuser != "off" {
		t.Errorf("the append-only role is a SUPERUSER, which no ACL binds. "+
			"is_superuser = %q", superuser)
	}

	for _, tc := range appendOnlyExpectations {
		allowed, detail := probeOnce(ctx, t, conn, tc.sql)
		switch {
		case allowed && !tc.allowed:
			t.Errorf("the append-only role is allowed to %s.\ndoc 05 §1 runs the MCP "+
				"under a role that can append and not delete; %s.\n  %s",
				tc.name, tc.why, detail)
		case !allowed && tc.allowed:
			t.Errorf("the append-only role cannot %s, and it must: %s.\n  %s",
				tc.name, tc.why, detail)
		default:
			t.Logf("OPS-009 %-34s allowed=%-5v  %s", tc.name, allowed, detail)
		}
	}
}

// probeOnce attempts one statement in a transaction it always rolls back.
//
// `allowed` is true when the ACL did NOT stop the statement — including when
// the statement got past the ACL and was then refused by one of the ledger's
// own triggers. The trigger is the ledger's guarantee, not this credential's,
// and a role the ACL lets through is a role that can write to anything the
// triggers do not cover. This is internal/api/readonly.go's rule, and the
// reason it is the right one is the measurement in this file's header.
func probeOnce(ctx context.Context, t *testing.T, conn *pgx.Conn, sql string) (bool, string) {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return true, "the probe could not be run: " + err.Error()
	}
	defer func() { discardRollback(tx.Rollback(ctx)) }()

	if _, err := tx.Exec(ctx, "SET TRANSACTION READ WRITE"); err != nil {
		return false, "refused before the statement ran (" + sqlState(err) + ")"
	}
	if _, err := tx.Exec(ctx, sql); err != nil {
		state := sqlState(err)
		if isPrivilegeRefusal(state) {
			return false, "refused by privilege (" + state + ")"
		}
		return true, "the ACL allowed the statement; it failed for another reason (" +
			state + "): " + firstLine(err.Error())
	}
	return true, "the statement succeeded and was rolled back"
}

// discardRollback swallows the rollback of a probe transaction. The probe's
// verdict is already recorded and a rollback that failed changes none of it;
// errcheck's check-blank makes the discard a named function rather than a
// blank assignment (internal/api/readonly.go's idiom).
func discardRollback(error) {}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------------------------------------------------------------------------
// OPS-010 (PROPOSED for doc 07's TC-OPS) — the shipped role check refuses an
// over-privileged credential, and the compose stack's schema is one the
// shipped migration runner recognises.
//
// Two halves, both about not trusting a claim.
//
// FIRST: a checker that never fails is not a check. deploy/compose/innsegl/
// verify-role.sh runs as a gate in front of the MCP; if it cannot be made to
// fail, its passing means nothing. So the role is deliberately widened by one
// GRANT — the exact "just fix one thing" an operator does — and the script has
// to catch it and name it.
//
// SECOND: db-init.sh applies the SHIPPED migrations from migrations/ and
// records them in innsegl.schema_migrations, which is internal/ledger's own
// bookkeeping table. If the compose stack's idea of "applied" ever stops
// matching the runner's, a later `innsegl serve -migrate` would re-apply
// migration 0001 against a schema that already has it. Rather than pinning the
// runner's SQL as text — which would drift silently — this asks the runner:
// Migrate() must succeed and must apply nothing.
// ---------------------------------------------------------------------------

func TestOPS010TheRoleCheckBitesAndTheSchemaIsTheRunners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg, err := startLedger(ctx, t)
	skip, failure := startupOutcome(err)
	if pg != nil {
		defer pg.stop()
	}
	switch containerRequirement(pg != nil, skip, failure) {
	case failTest:
		t.Fatalf("the ledger's Postgres did not start on a machine that has Docker: %s\n\n"+
			"This is a FAILURE and not a skip (#101).", failure)
	case skipTest:
		t.Skipf("skipping OPS-010: %s.", skip)
	case proceed:
	}

	root := repoRoot(t)
	if stageErr := pg.copyDeployScripts(ctx, root); stageErr != nil {
		t.Fatalf("staging the shipped deploy scripts: %v", stageErr)
	}
	if out, initErr := pg.runInit(ctx, "db-init.sh"); initErr != nil {
		t.Fatalf("db-init.sh failed: %v\n%s", initErr, out)
	}

	// ---- the gate passes on the role the deployment provisioned ------------
	if out, gateErr := pg.runInit(ctx, "verify-role.sh"); gateErr != nil {
		t.Fatalf("verify-role.sh rejected the role db-init.sh had just provisioned: %v\n%s",
			gateErr, out)
	} else {
		t.Logf("--- verify-role.sh, as provisioned ---\n%s", out)
	}

	// ---- and it has to bite ------------------------------------------------
	if grantErr := pg.psqlAsOwner(ctx,
		`GRANT DELETE ON innsegl.events TO `+appenderRole); grantErr != nil {
		t.Fatalf("widening the role for the negative case: %v", grantErr)
	}
	out, wideErr := pg.runInit(ctx, "verify-role.sh")
	if wideErr == nil {
		t.Errorf("verify-role.sh passed a role holding DELETE on innsegl.events.\n"+
			"A gate that cannot fail is not a gate, and this is the exact single "+
			"GRANT #109 is about — invisible to code review, caught only by asking "+
			"the server.\n%s", out)
	}
	if !strings.Contains(out, "DELETE") {
		t.Errorf("verify-role.sh refused but never named DELETE; an operator has to be "+
			"told which privilege to revoke.\n%s", out)
	}
	t.Logf("--- verify-role.sh, one GRANT later ---\n%s", out)
	if revokeErr := pg.psqlAsOwner(ctx,
		`REVOKE DELETE ON innsegl.events FROM `+appenderRole); revokeErr != nil {
		t.Fatalf("restoring the role: %v", revokeErr)
	}

	// ---- the schema is the migration runner's own --------------------------
	store, openErr := ledger.Open(ctx, pg.ownerDSN())
	if openErr != nil {
		t.Fatalf("opening the ledger the deploy scripts built: %v", openErr)
	}
	defer store.Close()

	before := migrationCount(ctx, t, pg)
	if migrateErr := store.Migrate(ctx); migrateErr != nil {
		t.Fatalf("the shipped migration runner rejected the schema deploy/compose "+
			"built: %v\n\nThe compose stack applies migrations/*.sql itself, so its "+
			"bookkeeping has to be the runner's bookkeeping — otherwise a later "+
			"`innsegl serve -migrate` re-applies migration 0001 over a schema that "+
			"already has it.", migrateErr)
	}
	if after := migrationCount(ctx, t, pg); after != before {
		t.Errorf("Migrate() applied %d migration(s) over a schema the deploy scripts "+
			"had already migrated (%d -> %d). The compose stack recorded something "+
			"the runner does not recognise.", after-before, before, after)
	}
	t.Logf("OPS-010 schema_migrations: %d rows, unchanged by the shipped runner", before)
}

func migrationCount(ctx context.Context, t *testing.T, pg *ledgerContainer) int {
	t.Helper()
	conn, err := pgx.Connect(ctx, pg.ownerDSN())
	if err != nil {
		t.Fatalf("connecting as the owner: %v", err)
	}
	defer func() { discardRollback(conn.Close(ctx)) }()
	var n int
	if countErr := conn.QueryRow(ctx,
		`SELECT count(*) FROM innsegl.schema_migrations`).Scan(&n); countErr != nil {
		t.Fatalf("counting applied migrations: %v", countErr)
	}
	return n
}
