// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/api"
)

// RM-330 (#506), ADR-0044's 2026-10-03 amendment — the resolver role in the
// reference stack.
//
// The dashboard resolves alerts through a credential that may insert an
// alert resolution and nothing else. db-init.sh provisions it from the SAME
// internal/api/resolver.sql api.EnsureResolverRole embeds, and
// verify-resolver-role.sh asks the server what it can do. Both halves are
// measured here: the shipped bootstrap yields a role `innsegl api` accepts,
// and the shipped check catches one GRANT too many.

func TestRM330DbInitProvisionsTheResolverRoleTheAPIAccepts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg := ledgerForTest(ctx, t, "RM-330", "the resolver role is the only credential "+
		"the dashboard may write with, so a skipped check is an unmeasured write path")
	provision(ctx, t, pg)

	pool, err := pgxpool.New(ctx, pg.resolverDSN())
	if err != nil {
		t.Fatalf("pgxpool.New(resolver): %v", err)
	}
	defer pool.Close()
	report, err := api.AssertResolverScope(ctx, pool)
	if err != nil {
		t.Fatalf("the role db-init.sh provisioned is not the one `innsegl api` accepts: %v", err)
	}
	if report.Ledger.Role != resolverRole {
		t.Errorf("connected as %q, want %q", report.Ledger.Role, resolverRole)
	}

	// One GRANT too many, the "just fix one thing" an operator does: the
	// shipped check must catch it and name it.
	if gerr := pg.psqlAsOwner(ctx, "GRANT UPDATE ON innsegl.alert_resolutions TO "+resolverRole); gerr != nil {
		t.Fatalf("widening the role: %v", gerr)
	}
	out, err := pg.runInit(ctx, "verify-resolver-role.sh")
	if err == nil {
		t.Fatalf("verify-resolver-role.sh passed a role that can UPDATE a resolution:\n%s", out)
	}
	if !strings.Contains(out, "update innsegl.alert_resolutions") {
		t.Errorf("verify-resolver-role.sh did not name the widened grant:\n%s", out)
	}
}
