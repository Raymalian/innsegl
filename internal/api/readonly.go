// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The read-only credential, and the proof that it is one.
//
// FD §7 requires a frontend that "holds no credentials capable of writing
// anywhere". #48 makes the mechanism explicit: the enforcement is a read-only
// database ROLE, and the absence of write code is only a convention. This file
// is both halves — the provisioning, and the assertion that runs before the
// API will serve a single request.
//
// The assertion matters more than the provisioning. A role is provisioned once
// and then lives in somebody's deployment; a later `GRANT` by an operator who
// wanted to "just fix one thing" is invisible to any amount of code review. So
// Open asks the server, every time it starts, whether the credential it was
// handed can write — and refuses to come up if it can.

// ErrWritable is a credential this API refuses to hold.
var ErrWritable = errors.New("api: the database credential is not read-only")

// ReadOnlyRole is the Postgres role the query API connects as. It is a default
// and not a protected string: a deployment may name it anything, and
// EnsureReadOnlyRole takes the name as an argument.
const ReadOnlyRole = "innsegl_reader"

//go:embed readonly.sql
var readOnlyGrants string

// Probe is one write the API's credential must not be allowed to make.
//
// Every probe runs inside a transaction that is always rolled back, and every
// one is preceded by `SET TRANSACTION READ WRITE` so that what refuses it is
// the GRANT rather than default_transaction_read_only — a setting any session
// can turn off for itself, and therefore not a boundary.
type Probe struct {
	Name string
	SQL  string
}

// ProbeResult is one probe's outcome, as evidence rather than as a verdict.
//
// Allowed is true when the ACL did NOT stop the statement. That includes the
// case where the statement got past the ACL and was then refused by one of the
// ledger's append-only triggers (SQLSTATE IN001/IN002): the trigger is the
// ledger's guarantee, not this credential's, and a role the ACL lets through
// is a role that can write to anything the triggers do not cover.
type ProbeResult struct {
	Name     string `json:"name"`
	Allowed  bool   `json:"allowed"`
	SQLState string `json:"sqlstate,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// ReadOnlyReport is what AssertReadOnly established, in full. It is served on
// the health surface so that "read-only" is a measured fact an operator can
// read back rather than a claim in a README.
type ReadOnlyReport struct {
	Role                       string        `json:"role"`
	Superuser                  bool          `json:"superuser"`
	DefaultTransactionReadOnly bool          `json:"default_transaction_read_only"`
	Probes                     []ProbeResult `json:"probes"`
}

// Writable reports whether any probe got past the ACL.
func (r ReadOnlyReport) Writable() bool {
	if r.Superuser {
		return true
	}
	for _, p := range r.Probes {
		if p.Allowed {
			return true
		}
	}
	return false
}

// writeProbes is the set of writes a credential must be refused.
//
// The three ledger tables, a table of the role's own in each of the two
// schemas, and a schema of its own to put one in. The last three matter as
// much as the first three: a role with CREATE anywhere is a role that can
// write, and "it has no INSERT on innsegl.events" would be a comforting half
// of the answer.
//
// SELECT ... FOR UPDATE stands in for UPDATE and DELETE on innsegl.events and
// innsegl.chain. It is the same privilege check, and it is the only one that
// reaches the ACL at all: migration 0001 puts a BEFORE ... FOR EACH STATEMENT
// trigger on both tables, so an UPDATE is refused for EVERY role including the
// owner, and a probe that used one could never convict a writing credential.
func writeProbes() []Probe {
	return []Probe{
		{"lock innsegl.events for update", `SELECT chain_position FROM innsegl.events FOR UPDATE`},
		{"insert into innsegl.events", `INSERT INTO innsegl.events
			(chain_position, event_id, event_hash, prev_event_hash, event_type,
			 source, ts, canonical)
		 VALUES (1, '00000000-0000-7000-8000-000000000000',
			 'sha256:` + strings.Repeat("0", 64) + `',
			 'sha256:` + strings.Repeat("1", 64) + `',
			 'run_registered', 'mcp', now(), '\x7b7d'::bytea)`},
		{"lock innsegl.chain for update", `SELECT chain_id FROM innsegl.chain FOR UPDATE`},
		{"insert into innsegl.idempotency", `INSERT INTO innsegl.idempotency
			(idempotency_key, tool, request_digest, status, lease_expires_at)
		 VALUES ('api-write-probe', 'probe',
			 'sha256:` + strings.Repeat("0", 64) + `', 'in_progress', now())`},
		{"delete from innsegl.idempotency", `DELETE FROM innsegl.idempotency
		 WHERE idempotency_key = 'api-write-probe'`},
		{"create a table in schema innsegl", `CREATE TABLE innsegl.api_write_probe (x int)`},
		{"create a table in schema public", `CREATE TABLE public.api_write_probe (x int)`},
		{"create a schema of its own", `CREATE SCHEMA api_write_probe`},
	}
}

// The two SQLSTATEs that are a refusal BY PRIVILEGE.
//
//	42501 insufficient_privilege   — the ACL said no.
//	25006 read_only_sql_transaction — the transaction is read-only.
//
// Anything else, including success, means the ACL let the statement through.
const (
	sqlStateInsufficientPrivilege = "42501"
	sqlStateReadOnlyTransaction   = "25006"
)

func isPrivilegeRefusal(code string) bool {
	return code == sqlStateInsufficientPrivilege || code == sqlStateReadOnlyTransaction
}

var roleNamePattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_$]{0,62}$`)

// EnsureReadOnlyRole creates the role if it is absent and applies readonly.sql
// to it, using an ADMINISTRATIVE dsn.
//
// This is operator tooling and it is deliberately not something the API can
// do: the credential the API runs on could not execute a single statement
// below. Handing it a DSN that could would defeat the whole arrangement.
//
// An empty password leaves the role's authentication alone, which is what a
// deployment authenticating by certificate, IAM or peer wants.
func EnsureReadOnlyRole(ctx context.Context, adminDSN, role, password string) error {
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

	ident := pgx.Identifier{role}.Sanitize()
	var exists bool
	if lerr := admin.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); lerr != nil {
		return fmt.Errorf("api: looking up the role %s: %w", role, lerr)
	}
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

	grants := fmt.Sprintf(readOnlyGrants, ident, pgx.Identifier{database}.Sanitize())
	if _, err := admin.Exec(ctx, grants); err != nil {
		return fmt.Errorf("api: applying the read-only grants to %s: %w", role, err)
	}
	return nil
}

// quoteLiteral renders a string as an SQL literal. Used for exactly one value
// — a password in a CREATE ROLE, which cannot be a bind parameter — and for
// nothing that comes from a request.
func quoteLiteral(s string) string {
	quoted := "'" + strings.ReplaceAll(s, "'", "''") + "'"
	if strings.Contains(s, `\`) {
		// standard_conforming_strings is on by default, so a backslash is
		// literal in an ordinary literal; an E-string is the only form in
		// which it can be escaped unambiguously.
		return "E" + strings.ReplaceAll(quoted, `\`, `\\`)
	}
	return quoted
}

// AssertReadOnly asks the server what this credential can do, and returns an
// error wrapping ErrWritable if the answer is "write".
//
// It writes nothing: every probe is rolled back, and the probes that a writing
// credential would be ALLOWED to run are the ones whose effect is discarded
// with the transaction. Running it against a production database is safe, and
// it is meant to be run there — that is the point of asking the server rather
// than reading the code.
func AssertReadOnly(ctx context.Context, c conn) (ReadOnlyReport, error) {
	var report ReadOnlyReport

	var superuser, readOnly string
	if err := c.QueryRow(ctx,
		`SELECT current_user, current_setting('is_superuser'),
		        current_setting('default_transaction_read_only')`,
	).Scan(&report.Role, &superuser, &readOnly); err != nil {
		return report, fmt.Errorf("api: reading the session's own identity: %w", err)
	}
	report.Superuser = superuser == "on"
	report.DefaultTransactionReadOnly = readOnly == "on"

	for _, p := range writeProbes() {
		report.Probes = append(report.Probes, probeOnce(ctx, c, p))
	}
	if !report.Writable() {
		return report, nil
	}

	var allowed []string
	if report.Superuser {
		allowed = append(allowed, "it is a SUPERUSER, which no ACL binds")
	}
	for _, r := range report.Probes {
		if r.Allowed {
			allowed = append(allowed, r.Name)
		}
	}
	return report, fmt.Errorf("%w: the role %q is allowed to: %s. FD §7 requires a "+
		"credential incapable of writing anywhere; provision one with "+
		"EnsureReadOnlyRole and point the API at that",
		ErrWritable, report.Role, strings.Join(allowed, "; "))
}

// probeOnce attempts one write in a transaction it always rolls back.
func probeOnce(ctx context.Context, c conn, p Probe) ProbeResult {
	out := ProbeResult{Name: p.Name}

	tx, err := c.Begin(ctx)
	if err != nil {
		out.Allowed = true
		out.Detail = "the probe could not be run: " + err.Error()
		return out
	}
	defer func() { discardError(tx.Rollback(ctx)) }()

	// Defeat default_transaction_read_only, so that a refusal below is the
	// ACL's and not a setting's. If even this is refused, that too is a
	// refusal — recorded rather than treated as an error.
	if _, err := tx.Exec(ctx, "SET TRANSACTION READ WRITE"); err != nil {
		out.SQLState, out.Detail = sqlState(err), err.Error()
		return out
	}

	if _, err := tx.Exec(ctx, p.SQL); err != nil {
		out.SQLState, out.Detail = sqlState(err), err.Error()
		out.Allowed = !isPrivilegeRefusal(out.SQLState)
		if out.Allowed {
			out.Detail = "the ACL allowed the statement; it failed for another " +
				"reason (" + out.SQLState + "): " + err.Error()
		}
		return out
	}
	out.Allowed = true
	out.Detail = "the statement succeeded and was rolled back"
	return out
}

// discardError swallows an error a caller genuinely cannot act on. errcheck
// runs with check-blank here, so the discard is a named function rather than a
// blank assignment — the same idiom internal/verify's fixtures use, and for
// the same reason: a discard should be visible and explained, not invisible.
func discardError(error) {}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
