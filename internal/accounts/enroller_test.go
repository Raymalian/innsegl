// SPDX-License-Identifier: Apache-2.0

package accounts

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"innsegl.dev/innsegl/internal/api"
)

// LED-049 (RM-355, #603): the enroller role the core holds.
//
// The core enrols, renews and revokes machines. Until #603 it did that as
// the auth-writer, which may read and write every sign-in table: users,
// passkeys, sessions. The enroller may run exactly the statements the core's
// own code paths issue and is refused (42501) everything else the auth-writer
// may do. Both halves are measured against the server, never read off the
// GRANTs.

const enrollerPassword = "enroller-test-password"

// enrollerDSN provisions the enroller in e's database with the shipped
// grants, and answers its connection string.
func (e *env) enrollerDSN(t *testing.T) string {
	t.Helper()
	if err := api.EnsureEnrollerRole(tctx(t), e.ownerDSN, api.EnrollerRole, enrollerPassword); err != nil {
		t.Fatalf("EnsureEnrollerRole: %v", err)
	}
	return e.pg.dsn(e.database, api.EnrollerRole, enrollerPassword)
}

// enrollerScope is every privilege the enroller holds on innsegl_auth, as the
// server answers it: "table.PRIV(column)" for a column privilege and
// "table.PRIV" for a table-only one. "*" stands for every column the table has.
var enrollerScope = map[string]map[string][]string{
	"enrolment_tokens": {"SELECT": {"*"}, "UPDATE": {"used_at", "installation_id"}},
	"installations": {
		"SELECT": {"*"},
		"INSERT": {"installation_id", "account_id", "created_by", "name", "kind", "repos"},
		"UPDATE": {"last_renewed_at", "status", "revoked_at", "operator_author_name", "operator_author_email"},
	},
	"repo_grants": {"SELECT": {"*"}, "INSERT": {"account_id", "repo"}},
	"audit":       {"INSERT": {"actor", "account_id", "action", "subject", "detail"}},
	"accounts":    {"SELECT": {"*"}},
	"memberships": {"SELECT": {"*"}},
}

var columnPrivs = []string{"SELECT", "INSERT", "UPDATE", "REFERENCES"}
var tablePrivs = []string{"DELETE", "TRUNCATE", "TRIGGER"}

type authColumn struct{ table, column string }

func authColumns(ctx context.Context, t *testing.T, c *pgx.Conn) []authColumn {
	t.Helper()
	rows, err := c.Query(ctx, `SELECT c.relname, a.attname
		  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'innsegl_auth' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
		 ORDER BY 1, a.attnum`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (authColumn, error) {
		var col authColumn
		return col, r.Scan(&col.table, &col.column)
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// privileges answers every privilege role holds on innsegl_auth's tables and
// sequences, as the server reports it.
func privileges(t *testing.T, e *env, role string) []string {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	var out []string
	tables := map[string]bool{}
	for _, col := range authColumns(ctx, t, c) {
		tables[col.table] = true
		for _, p := range columnPrivs {
			var ok bool
			if err := c.QueryRow(ctx, `SELECT has_column_privilege($1, $2, $3, $4)`,
				role, "innsegl_auth."+col.table, col.column, p).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			if ok {
				out = append(out, fmt.Sprintf("%s.%s(%s)", col.table, p, col.column))
			}
		}
	}
	for table := range tables {
		for _, p := range tablePrivs {
			var ok bool
			if err := c.QueryRow(ctx, `SELECT has_table_privilege($1, $2, $3)`,
				role, "innsegl_auth."+table, p).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			if ok {
				out = append(out, table+"."+p)
			}
		}
	}
	rows, err := c.Query(ctx, `SELECT s.relname, p.priv
		  FROM pg_class s JOIN pg_namespace n ON n.oid = s.relnamespace
		  CROSS JOIN unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS p(priv)
		 WHERE n.nspname = 'innsegl_auth' AND s.relkind = 'S'
		   AND has_sequence_privilege($1, s.oid, p.priv)`, role)
	if err != nil {
		t.Fatal(err)
	}
	seqs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var s, p string
		serr := r.Scan(&s, &p)
		return "sequence " + s + "." + p, serr
	})
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, seqs...)
	sort.Strings(out)
	return out
}

func expectedEnrollerPrivileges(t *testing.T, e *env) []string {
	t.Helper()
	c, ctx := ownerConn(t, e.ownerDSN)
	var out []string
	for _, col := range authColumns(ctx, t, c) {
		for p, cols := range enrollerScope[col.table] {
			if slices.Contains(cols, "*") || slices.Contains(cols, col.column) {
				out = append(out, fmt.Sprintf("%s.%s(%s)", col.table, p, col.column))
			}
		}
	}
	sort.Strings(out)
	return out
}

// statementFor is one statement that needs exactly the privilege p names.
func statementFor(p string) string {
	if strings.HasPrefix(p, "sequence ") {
		name, _, _ := strings.Cut(strings.TrimPrefix(p, "sequence "), ".")
		return fmt.Sprintf(`SELECT nextval('innsegl_auth.%s')`, name)
	}
	table, rest, _ := strings.Cut(p, ".")
	priv, col, _ := strings.Cut(strings.TrimSuffix(rest, ")"), "(")
	qt := "innsegl_auth." + pgx.Identifier{table}.Sanitize()
	qc := pgx.Identifier{col}.Sanitize()
	switch priv {
	case "SELECT":
		return fmt.Sprintf("SELECT %s FROM %s WHERE false", qc, qt)
	case "INSERT":
		return fmt.Sprintf("INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT NULL WHERE false", qt, qc)
	case "UPDATE":
		return fmt.Sprintf("UPDATE %s SET %s = DEFAULT WHERE false", qt, qc)
	case "DELETE":
		return fmt.Sprintf("DELETE FROM %s WHERE false", qt)
	}
	return ""
}

// discardRollback swallows the rollback's error: the probe's transaction is
// thrown away either way.
func discardRollback(error) {}

// refusedState runs stmt as the pool's role in a transaction it rolls back,
// and answers the SQLSTATE it failed with ("" when it ran).
func refusedState(t *testing.T, s *Store, stmt string) string {
	t.Helper()
	ctx := tctx(t)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { discardRollback(tx.Rollback(ctx)) }()
	if _, err := tx.Exec(ctx, stmt); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return pe.Code
		}
		t.Fatalf("%s: %v", stmt, err)
	}
	return ""
}

func TestLED049TheEnrollerRunsEnrolmentsStatementsAndNothingElse(t *testing.T) {
	e, writer, a := setup(t)
	enroller, err := OpenEnroller(tctx(t), e.enrollerDSN(t))
	if err != nil {
		t.Fatalf("OpenEnroller(enroller): %v", err)
	}
	t.Cleanup(enroller.Close)

	// What the API does, with the auth-writer: a token, and a grant held.
	if gerr := writer.GrantRepo(tctx(t), a.ID, "github.com/acme/held", "u-1"); gerr != nil {
		t.Fatal(gerr)
	}
	tok, _, err := writer.CreateEnrolmentToken(tctx(t), TokenParams{AccountID: a.ID, CreatedBy: "u-1"})
	if err != nil {
		t.Fatal(err)
	}

	// Every statement the core issues, as the enroller.
	issue := func(context.Context, Installation) error { return nil }
	inst, err := enroller.Enrol(tctx(t), EnrolParams{Token: tok, InstallationID: testInstallationID, Name: "laptop"}, issue)
	if err != nil {
		t.Fatalf("enrol as the enroller: %v", err)
	}
	if _, err := enroller.Renew(tctx(t), inst.ID, issue); err != nil {
		t.Fatalf("renew as the enroller: %v", err)
	}
	if _, err := enroller.GetInstallation(tctx(t), inst.ID); err != nil {
		t.Fatalf("read the installation as the enroller: %v", err)
	}
	if in, err := enroller.ClaimRepo(tctx(t), inst.ID, "github.com/acme/new"); err != nil || !in {
		t.Fatalf("claim a repository on first use as the enroller: %v, %v", in, err)
	}
	if in, err := enroller.ClaimRepo(tctx(t), inst.ID, "github.com/acme/held"); err != nil || !in {
		t.Fatalf("claim a held repository as the enroller: %v, %v", in, err)
	}
	if in, err := enroller.InScope(tctx(t), inst.ID, "github.com/acme/new"); err != nil || !in {
		t.Fatalf("scope as the enroller: %v, %v", in, err)
	}
	if _, err := enroller.PinOperatorAuthor(tctx(t), inst.ID, "octo", "1+octo@users.noreply.github.com"); err != nil {
		t.Fatalf("pin the operator author as the enroller: %v", err)
	}
	if _, _, ok, err := enroller.OperatorAuthor(tctx(t), inst.ID); err != nil || !ok {
		t.Fatalf("read the operator author as the enroller: %v, %v", ok, err)
	}
	if got, err := enroller.ListAccounts(tctx(t)); err != nil || len(got) != 1 {
		t.Fatalf("list organisations as the enroller: %v, %v", got, err)
	}
	if got, err := enroller.Memberships(tctx(t), "u-1"); err != nil || len(got) != 1 {
		t.Fatalf("memberships as the enroller: %v, %v", got, err)
	}
	if err := enroller.SetInstallationStatus(tctx(t), inst.ID, StatusRevoked, ClaimActor(inst.ID)); err != nil {
		t.Fatalf("revoke as the enroller: %v", err)
	}

	// Exactly that scope, as the server answers it.
	got, want := privileges(t, e, api.EnrollerRole), expectedEnrollerPrivileges(t, e)
	if !slices.Equal(got, want) {
		t.Errorf("the enroller holds:\n  %s\nwant exactly:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	// Everything else the auth-writer may do is refused by privilege.
	held := map[string]bool{}
	for _, p := range got {
		held[p] = true
	}
	refused := 0
	for _, p := range privileges(t, e, api.AuthWriterRole) {
		if held[p] {
			continue
		}
		stmt := statementFor(p)
		if stmt == "" {
			t.Fatalf("no statement for the auth-writer's %s", p)
		}
		if state := refusedState(t, enroller, stmt); state != "42501" {
			t.Errorf("%s as the enroller: SQLSTATE %q, want 42501 (%s)", p, state, stmt)
		}
		refused++
	}
	if refused < 50 {
		t.Errorf("only %d of the auth-writer's privileges were probed; the comparison is not measuring", refused)
	}
}

// LED-049: the core refuses the auth-writer as its enrolment credential, and
// a credential that cannot enrol.
func TestLED049TheEnrollerCredentialIsAssertedAtOpen(t *testing.T) {
	e, _ := migrated(t)
	dsn := e.enrollerDSN(t)

	pool, err := OpenEnroller(tctx(t), dsn)
	if err != nil {
		t.Fatalf("OpenEnroller(enroller): %v", err)
	}
	report, err := api.AssertEnrollerScope(tctx(t), pool.pool)
	pool.Close()
	if err != nil || report.Ledger.Role != api.EnrollerRole {
		t.Fatalf("AssertEnrollerScope(enroller) = %+v, %v", report, err)
	}

	if _, err := OpenEnroller(tctx(t), e.writer); !errors.Is(err, api.ErrWritable) {
		t.Fatalf("OpenEnroller(auth-writer) = %v, want ErrWritable: the core must not hold the auth-writer", err)
	}

	// A role that cannot spend a token.
	c, ctx := ownerConn(t, e.ownerDSN)
	if _, err := c.Exec(ctx, `REVOKE UPDATE ON innsegl_auth.enrolment_tokens FROM `+api.EnrollerRole); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEnroller(tctx(t), dsn); !errors.Is(err, api.ErrEnrollerCannotEnrol) {
		t.Fatalf("OpenEnroller(no token spend) = %v, want ErrEnrollerCannotEnrol", err)
	}
}
