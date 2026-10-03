// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/ledger"
)

// The resolver credential, and the proof that it can do one thing.
//
// ADR-0044's 2026-10-03 amendment (RM-330, #506): the dashboard resolves
// alerts after a fresh passkey ceremony. The write goes through a THIRD
// database credential, beside the read-only one (readonly.go) and the auth
// writer (authwriter.go), and it is the narrowest of the three: it may insert
// a row into innsegl.alert_resolutions and nothing else. resolver.sql is the
// grant; AssertResolverScope asks the server whether the grant is what the
// process was actually handed, at every start, the same way AssertReadOnly
// does for the reader. The read-only pool never sees this credential, and
// AssertReadOnly still refuses it a writable one.

// ResolverRole is the Postgres role the API's resolution half connects as. A
// default, not a protected string, exactly as ReadOnlyRole is.
const ResolverRole = "innsegl_resolver"

//go:embed resolver.sql
var resolverGrants string

// ErrResolverCannotResolve is a resolver credential that cannot make the one
// write it exists for. Holding it would offer a button that always fails.
var ErrResolverCannotResolve = errors.New("api: the resolver credential cannot insert an alert resolution")

// The probes AssertResolverScope adds to AssertReadOnly's. The first must be
// allowed; the other three must be refused.
const (
	probeInsertResolution = "insert into innsegl.alert_resolutions"
	probeUpdateResolution = "update innsegl.alert_resolutions"
	probeDeleteResolution = "delete from innsegl.alert_resolutions"
	probeReadAuth         = "read innsegl_auth.users"
)

func resolverProbes() []Probe {
	return []Probe{
		{probeInsertResolution, `INSERT INTO innsegl.alert_resolutions (event_id, resolved_by, reason)
			VALUES ('00000000-0000-7000-8000-000000000000', 'resolver-probe', 'resolver-probe')`},
		{probeUpdateResolution, `UPDATE innsegl.alert_resolutions SET reason = reason WHERE false`},
		{probeDeleteResolution, `DELETE FROM innsegl.alert_resolutions WHERE false`},
		{probeReadAuth, `SELECT 1 FROM innsegl_auth.users LIMIT 1`},
	}
}

// ResolverReport is what AssertResolverScope established: the reader's own
// probes, run against this credential, and the four of its own.
type ResolverReport struct {
	Ledger ReadOnlyReport `json:"ledger"`
	Probes []ProbeResult  `json:"probes"`
}

// EnsureResolverRole creates the role if it is absent and applies
// resolver.sql to it, using an ADMINISTRATIVE dsn — operator tooling, like
// EnsureReadOnlyRole and EnsureAuthWriterRole.
func EnsureResolverRole(ctx context.Context, adminDSN, role, password string) error {
	return ensureRole(ctx, adminDSN, role, password, resolverGrants, "resolver")
}

// ensureRole is the shared body of the Ensure*Role functions: create or
// alter the login role, then apply its grant file with the role and database
// identifiers substituted after pgx has sanitised them.
func ensureRole(ctx context.Context, adminDSN, role, password, grantSQL, what string) error {
	if !roleNamePattern.MatchString(role) {
		return fmt.Errorf("api: %q is not a usable role name", role)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return fmt.Errorf("api: connecting as the administrator: %w", err)
	}
	defer func() { discardError(admin.Close(ctx)) }()

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

	grants := fmt.Sprintf(grantSQL, ident, pgx.Identifier{database}.Sanitize())
	if _, err := admin.Exec(ctx, grants); err != nil {
		return fmt.Errorf("api: applying the %s grants to %s: %w", what, role, err)
	}
	return nil
}

// AssertResolverScope asks the server what the resolver credential may do.
// It refuses, wrapping ErrWritable, a credential that can write anything
// AssertReadOnly protects or can update, delete or read what it must not;
// and refuses, wrapping ErrResolverCannotResolve, one that cannot insert a
// resolution. Every probe is rolled back: it writes nothing.
func AssertResolverScope(ctx context.Context, c conn) (ResolverReport, error) {
	var report ResolverReport
	ledgerReport, err := AssertReadOnly(ctx, c)
	report.Ledger = ledgerReport
	if err != nil {
		return report, fmt.Errorf("api: the resolver credential can do more than resolve "+
			"alerts (ADR-0044 amendment): %w", err)
	}

	var beyond []string
	insertAllowed := false
	for _, p := range resolverProbes() {
		result := probeOnce(ctx, c, p)
		report.Probes = append(report.Probes, result)
		switch {
		case p.Name == probeInsertResolution:
			insertAllowed = result.Allowed
		case result.Allowed:
			beyond = append(beyond, p.Name)
		}
	}
	if len(beyond) > 0 {
		return report, fmt.Errorf("%w: the resolver role %q is allowed to: %s. It may insert "+
			"an alert resolution and nothing else; provision it with EnsureResolverRole",
			ErrWritable, report.Ledger.Role, strings.Join(beyond, "; "))
	}
	if !insertAllowed {
		return report, fmt.Errorf("%w: the role %q; provision it with EnsureResolverRole",
			ErrResolverCannotResolve, report.Ledger.Role)
	}
	return report, nil
}

// Resolver is the API's handle on the resolver credential: the pool, the
// one write ledger.AlertResolver makes through it, and the evidence that the
// credential is scoped to that write.
type Resolver struct {
	pool   *pgxpool.Pool
	alerts *ledger.AlertResolver
	scope  ResolverReport
}

// OpenResolver opens a pool on dsn and refuses it unless AssertResolverScope
// accepts it.
func OpenResolver(ctx context.Context, dsn string) (*Resolver, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("api: parsing the resolver DSN: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("api: opening the resolver pool: %w", err)
	}
	scope, err := AssertResolverScope(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &Resolver{pool: pool, alerts: ledger.NewAlertResolver(pool), scope: scope}, nil
}

// Close releases the pool.
func (r *Resolver) Close() { r.pool.Close() }

// Scope is the evidence OpenResolver gathered, served on the health surface.
func (r *Resolver) Scope() ResolverReport { return r.scope }
