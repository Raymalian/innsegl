// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// MCP-097's refusal and failure paths (ADR-0080): what a pseudonymous append
// refuses before the database, what it does when the alias cannot be
// written, and how every read reports a ledger that cannot answer.

func TestMCP097APseudonymousAppendRefusesWhatItCannotHide(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	s.UseRepositories(pseudonymous(t, pnKeyA))

	for _, tc := range []struct {
		name string
		body event.Fields
		want error
	}{
		{"a repository that is not host/org/name", registeredIn("run-x1", "not-a-repo", "main", 1), event.ErrInvalidRepo},
		{"a branch git would refuse", registeredIn("run-x2", pnRepo, "a..b", 2), event.ErrInvalidBranch},
		{"a literal branch beside a pseudonymous repository", func() event.Fields {
			b := registeredIn("run-x3", "pn:rk-0a1b2c3d:"+strings.Repeat("a", 32), "main", 3)
			return b
		}(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Append(ctx, tc.body)
			var se *StoreError
			if !errors.As(err, &se) || se.Class != ClassInvariantViolation {
				t.Fatalf("err = %v, want an INVARIANT_VIOLATION", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if n := len(canonicalRows(t, s)); n != 0 {
		t.Errorf("%d events appended by refused appends", n)
	}
	if n := len(aliasRows(t, s)); n != 0 {
		t.Errorf("%d aliases written by refused appends", n)
	}

	t.Run("a detached HEAD writes no branch alias", func(t *testing.T) {
		rec, err := s.Append(ctx, registeredIn("run-detached", pnRepo, "detached", 4))
		if err != nil || rec[event.FieldBranch] != "detached" {
			t.Fatalf("append = %v, %v", rec[event.FieldBranch], err)
		}
		if n := len(aliasRows(t, s)); n != 1 {
			t.Errorf("%d aliases, want the repository's alone", n)
		}
	})
}

func TestMCP097AnAliasThatCannotBeWrittenFailsTheAppend(t *testing.T) {
	s, dsn := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	s.UseRepositories(pseudonymous(t, pnKeyA))
	conn := rawConn(t, dsn)
	if _, err := conn.Exec(ctx, `
		CREATE FUNCTION innsegl.test_refuse_alias() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'alias refused for the test' USING ERRCODE = 'XX001'; END $$;
		CREATE TRIGGER test_refuse_alias BEFORE INSERT ON innsegl.pseudonyms
		FOR EACH ROW EXECUTE FUNCTION innsegl.test_refuse_alias();`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, registeredIn("run-noalias", pnRepo, "main", 1)); err == nil {
		t.Fatal("the append succeeded with no alias to resolve it")
	}
	if n := len(canonicalRows(t, s)); n != 0 {
		t.Errorf("an event with no alias was appended (%d rows)", n)
	}
}

func TestMCP098ReadsReportALedgerThatCannotAnswer(t *testing.T) {
	s, _ := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	s.Close()
	pn := "pn:rk-0a1b2c3d:" + strings.Repeat("a", 32)
	wantUnavailable := func(t *testing.T, what string, err error) {
		t.Helper()
		var se *StoreError
		if !errors.As(err, &se) {
			t.Errorf("%s: err = %v, want a StoreError", what, err)
		}
	}

	_, err := s.ResolveNames(ctx, pn)
	wantUnavailable(t, "ResolveNames", err)
	_, err = s.Resolved(ctx, event.Fields{event.FieldRepo: pn})
	wantUnavailable(t, "Resolved", err)
	wantUnavailable(t, "RecordPseudonymous", s.RecordPseudonymous(ctx, "rk-0a1b2c3d"))
	_, err = s.RecordedPseudonymous(ctx)
	wantUnavailable(t, "RecordedPseudonymous", err)
	_, err = Resolving{Store: s}.EventsForRun(ctx, "run-x")
	wantUnavailable(t, "Resolving.EventsForRun", err)
	_, _, err = Resolving{Store: s}.EventByIdempotencyKey(ctx, "key")
	wantUnavailable(t, "Resolving.EventByIdempotencyKey", err)

	t.Run("literal values never reach the database", func(t *testing.T) {
		names, err := s.ResolveNames(ctx, "github.com/acme/api", "main")
		if err != nil || names["github.com/acme/api"] != "github.com/acme/api" || names["main"] != "main" {
			t.Errorf("ResolveNames(literals) = %v, %v", names, err)
		}
	})
}

// The resolving reads, when the run's records resolve but the alias table
// cannot be read: the read fails rather than answering pseudonyms as names.
func TestMCP098ResolvingFailsWhenTheAliasTableCannotBeRead(t *testing.T) {
	s, dsn := newStore(t)
	ctx := testCtx(t, 60*time.Second)
	s.UseRepositories(pseudonymous(t, pnKeyA))
	if _, err := s.Append(ctx, registeredIn("run-hidden", pnRepo, "main", 1)); err != nil {
		t.Fatal(err)
	}
	conn := rawConn(t, dsn)
	if _, err := conn.Exec(ctx, `ALTER TABLE innsegl.pseudonyms RENAME TO pseudonyms_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := (Resolving{Store: s}).EventsForRun(ctx, "run-hidden"); err == nil {
		t.Error("EventsForRun answered with no alias table")
	}
	if _, _, err := (Resolving{Store: s}).EventByIdempotencyKey(ctx, "run-scoped-run-hidden-1"); err == nil {
		t.Error("EventByIdempotencyKey answered with no alias table")
	}
}
