// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/migrations"
)

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// countMappingRows is a raw-SQL sanity read, used only to confirm a refused
// statement changed nothing -- the same role rawConn plays in
// internal/ledger/postgres_schema_test.go.
func countMappingRows(t *testing.T, dsn string) int64 {
	t.Helper()
	conn := rawMappingConn(t, dsn)
	var n int64
	if err := conn.QueryRow(testCtx(t, 10*time.Second),
		`SELECT count(*) FROM innsegl.gateway_run_mapping`).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// GID-007 -- the mapping table: INSERT succeeds; UPDATE, DELETE and TRUNCATE
// are refused by grant and trigger.
//
// The ACL half ("no UPDATE/DELETE/TRUNCATE grant") is deploy/compose's
// appendonly.sql, which already extends to a table added by a later
// migration through ALTER DEFAULT PRIVILEGES (migrations/0007's own doc
// comment) -- unchanged by this issue, and not a claim a Go integration test
// against the database OWNER can make, since an owner is never stopped by a
// grant. What this test measures directly, against a real Postgres,
// mirroring internal/ledger's TestChainLinkTriggerRefusesGapsAndForks, is the
// other half: the trigger refuses UPDATE, DELETE and TRUNCATE for ANY role,
// owner included, with SQLSTATE IN004 -- so ADR-0060 decision 3's guarantee
// does not rest on a grant an operator could quietly widen.
// ---------------------------------------------------------------------------

func TestGID007TheMappingTableIsInsertOnly(t *testing.T) {
	t.Parallel()
	store, dsn := newMigratedMappingStore(t)
	ctx := testCtx(t, 2*time.Minute)

	if err := store.Insert(ctx, RunMapping{
		RunID: "run-1", SessionID: "session-a", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if n := countMappingRows(t, dsn); n != 1 {
		t.Fatalf("%d rows after one insert, want 1", n)
	}

	conn := rawMappingConn(t, dsn)
	cases := []struct {
		name string
		sql  string
	}{
		{"UPDATE", `UPDATE innsegl.gateway_run_mapping SET run_id = 'tampered'`},
		{"DELETE", `DELETE FROM innsegl.gateway_run_mapping WHERE true`},
		{"TRUNCATE", `TRUNCATE innsegl.gateway_run_mapping`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := conn.Exec(ctx, c.sql)
			if err == nil {
				t.Fatalf("a direct %s was accepted; the run mapping is not insert-only", c.name)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("%s failed with %v, not a Postgres error", c.name, err)
			}
			if pgErr.Code != "IN004" {
				t.Fatalf("%s failed with SQLSTATE %s (%s), want IN004", c.name, pgErr.Code, pgErr.Message)
			}
			t.Logf("refused: SQLSTATE %s: %s", pgErr.Code, pgErr.Message)
		})
	}

	if n := countMappingRows(t, dsn); n != 1 {
		t.Fatalf("%d rows after three refused mutations, want 1 (unchanged)", n)
	}
}

// ---------------------------------------------------------------------------
// GID-008 -- a later row for the same key: lookup answers the latest row; a
// fingerprint added later is found by fingerprint.
// ---------------------------------------------------------------------------

func TestGID008ALaterRowSupersedesAnEarlierOneAndIsFoundByFingerprint(t *testing.T) {
	t.Parallel()
	store, _ := newMigratedMappingStore(t)
	ctx := testCtx(t, 2*time.Minute)

	const (
		sessionID = "session-b"
		agentID   = mainAgentID
		fp        = Fingerprint("fp-b1")
	)

	// The first request: no fingerprint yet (ADR-0058 decision 4 -- empty
	// until the conversation has a first assistant turn).
	if err := store.Insert(ctx, RunMapping{
		RunID: "run-first", SessionID: sessionID, AgentID: agentID,
	}); err != nil {
		t.Fatalf("insert the first row: %v", err)
	}

	got, found, err := store.BySessionAgent(ctx, sessionID, agentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent after the first row: found=%v err=%v", found, err)
	}
	if got.RunID != "run-first" {
		t.Fatalf("BySessionAgent = %+v, want run-first", got)
	}
	if got.Fingerprint != "" {
		t.Fatalf("the first row already carries a fingerprint: %+v", got)
	}

	// A later row for the same (session, agent): adds the fingerprint the
	// conversation's first assistant turn produced. Sleep past one clock
	// tick so the two rows do not race a monotonic clock's resolution; the
	// surrogate id, not the sleep, is what BySessionAgent actually relies on.
	time.Sleep(2 * time.Millisecond)
	if ierr := store.Insert(ctx, RunMapping{
		RunID: "run-first", SessionID: sessionID, AgentID: agentID, Fingerprint: fp,
	}); ierr != nil {
		t.Fatalf("insert the later row: %v", ierr)
	}

	got, found, err = store.BySessionAgent(ctx, sessionID, agentID)
	if err != nil || !found {
		t.Fatalf("BySessionAgent after the later row: found=%v err=%v", found, err)
	}
	if got.Fingerprint != fp {
		t.Fatalf("BySessionAgent answered fingerprint %q, want the later row's %q "+
			"(the lookup answered an earlier row instead of the latest)", got.Fingerprint, fp)
	}

	// The fingerprint the later row added is now itself a lookup key.
	byFP, err := store.ByFingerprint(ctx, fp)
	if err != nil {
		t.Fatalf("ByFingerprint: %v", err)
	}
	if len(byFP) != 1 || byFP[0].RunID != "run-first" || byFP[0].Fingerprint != fp {
		t.Fatalf("ByFingerprint(%q) = %+v, want exactly the later row", fp, byFP)
	}

	// A second run under the same fingerprint (a fork or an adoption, later
	// in the conversation) comes back after the first: ByFingerprint answers
	// oldest first, the same order the fake in lifecycle_fakes_test.go does.
	if ierr := store.Insert(ctx, RunMapping{
		RunID: "run-second", SessionID: sessionID, AgentID: agentID,
		Fingerprint: fp, ForkedFromRunID: "run-first",
	}); ierr != nil {
		t.Fatalf("insert the second run under the same fingerprint: %v", ierr)
	}
	byFP, err = store.ByFingerprint(ctx, fp)
	if err != nil {
		t.Fatalf("ByFingerprint after the fork: %v", err)
	}
	if len(byFP) != 2 || byFP[0].RunID != "run-first" || byFP[1].RunID != "run-second" {
		t.Fatalf("ByFingerprint(%q) = %+v, want [run-first, run-second] in that order", fp, byFP)
	}
	if byFP[1].ForkedFromRunID != "run-first" {
		t.Fatalf("the forked row's ForkedFromRunID is %q, want run-first", byFP[1].ForkedFromRunID)
	}

	// An empty fingerprint is never a lookup key: it means "none yet", not a
	// stored value to match against.
	none, err := store.ByFingerprint(ctx, "")
	if err != nil || len(none) != 0 {
		t.Fatalf("ByFingerprint(\"\") = %v, %v, want no rows and no error", none, err)
	}
}

// ---------------------------------------------------------------------------
// GID-009 -- gateway restart between two requests of one session: the second
// request continues the same run.
//
// A fresh PostgresMappingStore instance over the SAME database is the
// restart: nothing about the lookup may depend on anything the first
// instance held in memory, because a restarted gateway holds nothing of the
// first process at all.
// ---------------------------------------------------------------------------

func TestGID009ARestartedGatewayFindsTheSameLatestRun(t *testing.T) {
	t.Parallel()
	first, dsn := newMigratedMappingStore(t)
	ctx := testCtx(t, 2*time.Minute)

	const (
		sessionID = "session-c"
		agentID   = mainAgentID
	)
	if err := first.Insert(ctx, RunMapping{
		RunID: "run-before-restart", SessionID: sessionID, AgentID: agentID,
	}); err != nil {
		t.Fatalf("insert before the restart: %v", err)
	}

	// The gateway process this store belonged to exits.
	first.Close()

	// The gateway restarts: a brand-new store, over the same DSN, that has
	// never seen "first" and shares no Go value with it.
	second, err := OpenPostgresMappingStore(ctx, dsn)
	if err != nil {
		t.Fatalf("OpenPostgresMappingStore after the restart: %v", err)
	}
	defer second.Close()

	got, found, err := second.BySessionAgent(ctx, sessionID, agentID)
	if err != nil {
		t.Fatalf("BySessionAgent after the restart: %v", err)
	}
	if !found {
		t.Fatal("the restarted gateway's store found no run for a session and agent the prior process registered")
	}
	if got.RunID != "run-before-restart" {
		t.Fatalf("the restarted gateway continues run %q, want run-before-restart", got.RunID)
	}
}

// ---------------------------------------------------------------------------
// The upgrade path a running deployment actually takes: a database that
// already carries every migration through 0006, recorded exactly the way
// internal/ledger.Store.Migrate records one, gets 0007 applied -- and only
// 0007 -- the next time Migrate runs. Not a GID id of its own: this is a
// property of migrations.go's runner (frozen, untouched by this issue)
// applied to migrations/0007 specifically, the same way
// TestMigrateIsIdempotent already covers Migrate running twice over the
// whole embedded set.
// ---------------------------------------------------------------------------

func TestMigration0007AppliesOnADatabaseAlreadyAtThePreviousVersion(t *testing.T) {
	t.Parallel()
	c := requirePG(t)
	dsn := freshDatabase(t, c)
	ctx := testCtx(t, 2*time.Minute)

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}

	conn := rawMappingConn(t, dsn)
	if _, bootErr := conn.Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS innsegl;
		CREATE TABLE IF NOT EXISTS innsegl.schema_migrations (
			version    text PRIMARY KEY,
			name       text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		);`); bootErr != nil {
		t.Fatalf("bootstrap schema_migrations: %v", bootErr)
	}

	applied := 0
	for _, m := range all {
		if m.Version >= "0007" {
			continue
		}
		if _, applyErr := conn.Exec(ctx, m.SQL); applyErr != nil {
			t.Fatalf("apply %s directly, simulating a database already at the previous version: %v", m.Name, applyErr)
		}
		if _, recordErr := conn.Exec(ctx,
			`INSERT INTO innsegl.schema_migrations (version, name) VALUES ($1, $2)`,
			m.Version, m.Name); recordErr != nil {
			t.Fatalf("record %s as already applied: %v", m.Name, recordErr)
		}
		applied++
	}
	if applied == 0 {
		t.Fatal("no migration precedes 0007; this test proves nothing about an upgrade")
	}

	// The database is now exactly "already at the previous version": 0001
	// through 0006 recorded, 0007 not. This is the state a running
	// deployment's ledger database is in the moment this issue ships.
	led, openErr := ledger.Open(ctx, dsn)
	if openErr != nil {
		t.Fatalf("ledger.Open: %v", openErr)
	}
	defer led.Close()
	if migrateErr := led.Migrate(ctx); migrateErr != nil {
		t.Fatalf("Migrate on a database already at the previous version: %v", migrateErr)
	}

	var recordedVersion string
	if scanErr := conn.QueryRow(ctx,
		`SELECT version FROM innsegl.schema_migrations WHERE version = '0007'`).Scan(&recordedVersion); scanErr != nil {
		t.Fatalf("0007 was not recorded as applied after the upgrade: %v", scanErr)
	}

	// And the table it adds actually works: this is not only a row in
	// schema_migrations.
	store, storeErr := OpenPostgresMappingStore(ctx, dsn)
	if storeErr != nil {
		t.Fatalf("OpenPostgresMappingStore after the upgrade: %v", storeErr)
	}
	defer store.Close()
	if insertErr := store.Insert(ctx, RunMapping{
		RunID: "run-after-upgrade", SessionID: "session-upgrade", AgentID: mainAgentID,
	}); insertErr != nil {
		t.Fatalf("insert after the upgrade: %v", insertErr)
	}
	got, found, lookupErr := store.BySessionAgent(ctx, "session-upgrade", mainAgentID)
	if lookupErr != nil || !found || got.RunID != "run-after-upgrade" {
		t.Fatalf("BySessionAgent after the upgrade = %+v, found %v, err %v", got, found, lookupErr)
	}
}

// GW-019 (#460): a row inserted for a request the client guard verified
// carries the installation in client_id; a single-host row carries NULL.
func TestGW019TheMappingRowCarriesTheClientID(t *testing.T) {
	t.Parallel()
	store, dsn := newMigratedMappingStore(t)
	ctx := testCtx(t, 2*time.Minute)

	const inst = "0123456789abcdef0123456789abcdef"
	if err := store.Insert(WithInstallation(ctx, inst), RunMapping{
		RunID: "run-h", SessionID: "session-h", AgentID: mainAgentID,
	}); err != nil {
		t.Fatalf("Insert (hosted): %v", err)
	}
	if err := store.Insert(ctx, RunMapping{RunID: "run-l", SessionID: "session-l", AgentID: mainAgentID}); err != nil {
		t.Fatalf("Insert (single-host): %v", err)
	}
	conn := rawMappingConn(t, dsn)
	for run, want := range map[string]string{"run-h": inst, "run-l": ""} {
		var got *string
		if err := conn.QueryRow(ctx,
			`SELECT client_id FROM innsegl.gateway_run_mapping WHERE run_id = $1`, run).Scan(&got); err != nil {
			t.Fatalf("read client_id of %s: %v", run, err)
		}
		switch {
		case want == "" && got != nil:
			t.Errorf("%s client_id = %q, want NULL", run, *got)
		case want != "" && (got == nil || *got != want):
			t.Errorf("%s client_id = %v, want %q", run, got, want)
		}
	}
}
