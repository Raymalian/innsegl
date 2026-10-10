// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/erasure"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/identity"
)

// ADR-0080 on a real chain: MCP-097 (the append path writes pseudonyms and
// their aliases together), LED-046 (erasing an alias changes no byte of the
// chain), MCP-099 (dead runs of one repository are found across a mode switch
// and a key rotation) and OPS-175's ledger half (the switch is one-way).

const (
	pnRepo   = "example.test/acme/quiet-acquisition"
	pnBranch = "feature/before-disclosure"
	pnKeyA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pnKeyB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func pseudonymous(t *testing.T, key string) *identity.Repositories {
	t.Helper()
	r, err := identity.NewRepositories(identity.ModePseudonymous, key)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func registeredIn(runID, repo, branch string, n int) event.Fields {
	b := childBody(runID, "", n)
	b[event.FieldRepo] = repo
	b[event.FieldBranch] = branch
	return b
}

func intentIn(runID, repo string, n int) event.Fields {
	b := runScopedBody(runID, event.EventTypeCommitIntent, n)
	b[event.FieldRepo] = repo
	b[event.FieldTreeHash] = strings.Repeat("a", 40)
	b[event.FieldPatchID] = strings.Repeat("b", 40)
	return b
}

func aliasRows(t *testing.T, s *Store) map[string]string {
	t.Helper()
	ctx := testCtx(t, 30*time.Second)
	rows, err := s.pool.Query(ctx, `SELECT value, literal FROM innsegl.pseudonyms`)
	if err != nil {
		t.Fatalf("read aliases: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var v, l string
		if err := rows.Scan(&v, &l); err != nil {
			t.Fatal(err)
		}
		out[v] = l
	}
	return out
}

func canonicalRows(t *testing.T, s *Store) [][]byte {
	t.Helper()
	ctx := testCtx(t, 30*time.Second)
	rows, err := s.pool.Query(ctx, `SELECT canonical FROM innsegl.events ORDER BY chain_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// TestMCP097TheAppendPathWritesPseudonymsAndTheirAliasesTogether: a store in
// pseudonymous mode, handed the literal by every writer, stores only the
// pseudonym, and the alias that resolves it commits in the same transaction.
func TestMCP097TheAppendPathWritesPseudonymsAndTheirAliasesTogether(t *testing.T) {
	s, dsn := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	repos := pseudonymous(t, pnKeyA)
	s.UseRepositories(repos)

	wantRepo, _ := repos.Repo(pnRepo)
	wantBranch, _ := repos.Branch(pnRepo, pnBranch)

	reg, err := s.Append(ctx, registeredIn("run-pn", pnRepo, pnBranch, 1))
	if err != nil {
		t.Fatalf("append run_registered: %v", err)
	}
	if reg[event.FieldRepo] != wantRepo || reg[event.FieldBranch] != wantBranch {
		t.Errorf("stored repo, branch = %v, %v; want %q, %q",
			reg[event.FieldRepo], reg[event.FieldBranch], wantRepo, wantBranch)
	}
	intent, err := s.Append(ctx, intentIn("run-pn", pnRepo, 2))
	if err != nil {
		t.Fatalf("append commit_intent: %v", err)
	}
	if intent[event.FieldRepo] != wantRepo {
		t.Errorf("commit_intent repo = %v, want %q", intent[event.FieldRepo], wantRepo)
	}

	for i, c := range canonicalRows(t, s) {
		if bytes.Contains(c, []byte("acme")) || bytes.Contains(c, []byte("quiet")) ||
			bytes.Contains(c, []byte("disclosure")) {
			t.Errorf("event %d carries a literal name: %s", i+1, c)
		}
	}

	aliases := aliasRows(t, s)
	if aliases[wantRepo] != pnRepo || aliases[wantBranch] != pnBranch || len(aliases) != 2 {
		t.Errorf("aliases = %v, want the repository and the branch", aliases)
	}

	t.Run("a replay returns the first event and writes nothing", func(t *testing.T) {
		before := len(canonicalRows(t, s))
		again, err := s.Append(ctx, registeredIn("run-pn", pnRepo, pnBranch, 1))
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		if again[event.FieldEventID] != reg[event.FieldEventID] {
			t.Error("a replay wrote a second event")
		}
		if after := len(canonicalRows(t, s)); after != before || len(aliasRows(t, s)) != 2 {
			t.Errorf("a replay changed the chain (%d -> %d) or the aliases", before, after)
		}
	})

	t.Run("a value already pseudonymous passes through untouched", func(t *testing.T) {
		// The reconciler copies an intent's repo onto its repair: it is
		// already a pseudonym, possibly under an older key, and must not be
		// hidden twice.
		b := runScopedBody("run-pn", event.EventTypeCommitIntent, 3)
		b[event.FieldRepo] = wantRepo
		b[event.FieldTreeHash] = strings.Repeat("c", 40)
		b[event.FieldPatchID] = strings.Repeat("d", 40)
		rec, err := s.Append(ctx, b)
		if err != nil || rec[event.FieldRepo] != wantRepo {
			t.Errorf("append a pseudonymous repo = %v, %v", rec[event.FieldRepo], err)
		}
	})

	t.Run("a failed append leaves no alias behind", func(t *testing.T) {
		conn := rawConn(t, dsn)
		if _, err := conn.Exec(ctx, `
			CREATE FUNCTION innsegl.test_refuse_insert() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'refused for the test' USING ERRCODE = 'XX001'; END $$;
			CREATE TRIGGER test_refuse_insert BEFORE INSERT ON innsegl.events
			FOR EACH ROW EXECUTE FUNCTION innsegl.test_refuse_insert();`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append(ctx, registeredIn("run-lost", "example.test/acme/never-seen", "main", 9)); err == nil {
			t.Fatal("the append succeeded past a refusing trigger")
		}
		for _, l := range aliasRows(t, s) {
			if l == "example.test/acme/never-seen" || l == "main" {
				t.Errorf("an alias for %q survived the append that carried it", l)
			}
		}
		if _, err := conn.Exec(ctx, `DROP TRIGGER test_refuse_insert ON innsegl.events`); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a literal store writes the literal", func(t *testing.T) {
		l, _ := newStore(t)
		rec, err := l.Append(ctx, registeredIn("run-lit", pnRepo, pnBranch, 1))
		if err != nil || rec[event.FieldRepo] != pnRepo || rec[event.FieldBranch] != pnBranch {
			t.Errorf("literal append = %v, %v, %v", rec[event.FieldRepo], rec[event.FieldBranch], err)
		}
		if len(aliasRows(t, l)) != 0 {
			t.Error("a literal append wrote an alias")
		}
	})
}

// TestLED046ErasingAnAliasChangesNoByteOfTheChain is epic #478's exit
// criterion.
func TestLED046ErasingAnAliasChangesNoByteOfTheChain(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	repos := pseudonymous(t, pnKeyA)
	s.UseRepositories(repos)

	for i, b := range []event.Fields{
		registeredIn("run-a", pnRepo, pnBranch, 1),
		registeredIn("run-b", pnRepo, "main", 2),
		intentIn("run-a", pnRepo, 3),
		registeredIn("run-c", "example.test/acme/kept", "main", 4),
	} {
		if _, err := s.Append(ctx, b); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// A rotation: the same repository under a second key.
	s.UseRepositories(pseudonymous(t, pnKeyB))
	if _, err := s.Append(ctx, registeredIn("run-d", pnRepo, pnBranch, 5)); err != nil {
		t.Fatal(err)
	}

	before := canonicalRows(t, s)
	records, err := s.Events(ctx, 1, int64(len(before)))
	if err != nil {
		t.Fatal(err)
	}
	headBefore, err := Verify(records)
	if err != nil {
		t.Fatalf("the chain does not verify before erasure: %v", err)
	}
	repoA, _ := repos.Repo(pnRepo)

	n, err := erasure.Repository(ctx, s.pool, pnRepo)
	if err != nil {
		t.Fatalf("erasure.Repository: %v", err)
	}
	// Two repository pseudonyms (two keys) and three branch pseudonyms
	// (pnBranch and main under key A, pnBranch under key B).
	if n != 5 {
		t.Errorf("erased %d rows, want 5", n)
	}

	after := canonicalRows(t, s)
	if len(after) != len(before) {
		t.Fatalf("erasure changed the number of events: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Errorf("event %d changed under erasure", i+1)
		}
	}
	records, err = s.Events(ctx, 1, int64(len(after)))
	if err != nil {
		t.Fatal(err)
	}
	headAfter, err := Verify(records)
	if err != nil || headAfter != headBefore {
		t.Errorf("after erasure the chain verifies to %v (%v), was %v", headAfter, err, headBefore)
	}

	aliases := aliasRows(t, s)
	for v, l := range aliases {
		if l == pnRepo || l == pnBranch {
			t.Errorf("alias %s -> %s survived erasure", v, l)
		}
	}
	if len(aliases) != 2 {
		t.Errorf("aliases left = %v, want only the kept repository and its branch", aliases)
	}

	got, err := s.ResolveNames(ctx, repoA)
	if err != nil {
		t.Fatal(err)
	}
	if got[repoA] != repoA {
		t.Errorf("an erased pseudonym resolves to %q, want itself", got[repoA])
	}

	if n, err := erasure.Repository(ctx, s.pool, pnRepo); err != nil || n != 0 {
		t.Errorf("a second erasure = %d, %v; want 0, nil", n, err)
	}
	if _, err := erasure.Repository(ctx, s.pool, "not a repository"); !errors.Is(err, event.ErrInvalidRepo) {
		t.Errorf("erasing a non-repository = %v, want %v", err, event.ErrInvalidRepo)
	}
}

// TestMCP099DeadRunsAreFoundAcrossAModeSwitchAndAKeyRotation is the ledger
// half of adoption (ADR-0079) under ADR-0080: a commit's repository is the
// literal, and a dead run of it may be recorded literal (before the switch),
// under an older key id, or under the current one.
func TestMCP099DeadRunsAreFoundAcrossAModeSwitchAndAKeyRotation(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	retire := func(runID string) {
		t.Helper()
		if _, err := s.Append(ctx, runScopedBody(runID, event.EventTypeRunRetired, 0)); err != nil {
			t.Fatal(err)
		}
	}
	register := func(runID string, n int) {
		t.Helper()
		if _, err := s.Append(ctx, registeredIn(runID, pnRepo, "main", n)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append(ctx, runScopedBody(runID, event.EventTypeToolCall, n+100)); err != nil {
			t.Fatal(err)
		}
		retire(runID)
	}

	register("run-literal", 1)
	s.UseRepositories(pseudonymous(t, pnKeyA))
	register("run-key-a", 2)
	s.UseRepositories(pseudonymous(t, pnKeyB))
	register("run-key-b", 3)

	since := time.Now().Add(-time.Hour)
	got, err := s.DeadRunsForRepo(ctx, pnRepo, since, 10)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if want := []string{"run-key-a", "run-key-b", "run-literal"}; !slices.Equal(got, want) {
		t.Errorf("dead runs = %v, want %v", got, want)
	}

	if _, err := erasure.Repository(ctx, s.pool, pnRepo); err != nil {
		t.Fatal(err)
	}
	got, err = s.DeadRunsForRepo(ctx, pnRepo, since, 10)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"run-literal"}; !slices.Equal(got, want) {
		t.Errorf("after erasure dead runs = %v, want %v: the literal row stays literal (E7)", got, want)
	}
}

// TestOPS175TheSwitchToPseudonymousIsRecordedOnceAndNeverUndone is the
// ledger half of OPS-175.
func TestOPS175TheSwitchToPseudonymousIsRecordedOnceAndNeverUndone(t *testing.T) {
	s, dsn := newStore(t)
	ctx := testCtx(t, 60*time.Second)

	if on, err := s.RecordedPseudonymous(ctx); err != nil || on {
		t.Fatalf("a fresh ledger reports the switch recorded: %v, %v", on, err)
	}
	if err := s.RecordPseudonymous(ctx, "rk-0a1b2c3d"); err != nil {
		t.Fatalf("RecordPseudonymous: %v", err)
	}
	if err := s.RecordPseudonymous(ctx, "rk-ffffffff"); err != nil {
		t.Fatalf("a second RecordPseudonymous (a restart, or a new key) must be a no-op: %v", err)
	}
	if on, err := s.RecordedPseudonymous(ctx); err != nil || !on {
		t.Fatalf("after the switch RecordedPseudonymous = %v, %v", on, err)
	}

	conn := rawConn(t, dsn)
	for _, stmt := range []string{
		`DELETE FROM innsegl.repo_mode`,
		`UPDATE innsegl.repo_mode SET key_id = 'x'`,
		`TRUNCATE innsegl.repo_mode`,
	} {
		_, err := conn.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "IN005" {
			t.Errorf("%s as the owner = %v, want IN005", stmt, err)
		}
	}
}
