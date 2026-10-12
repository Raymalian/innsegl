// SPDX-License-Identifier: Apache-2.0

package ledgerdb

import (
	"context"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/test/deploy/deploytest"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/api"
)

// LED-049 (RM-355, #603) — the enroller role in the reference stack.
//
// The core enrols machines through a credential that holds enrolment's
// statements and nothing else. db-init.sh provisions it from the SAME
// internal/api/enroller.sql api.EnsureEnrollerRole embeds, and
// verify-enroller-role.sh asks the server what it can do. Both halves are
// measured here: the shipped bootstrap yields a role the core accepts, the
// shipped check catches one GRANT too many, and a second run narrows it
// again (an existing deployment's `make update`).
func TestLED049DbInitProvisionsTheEnrollerTheCoreAccepts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pg := ledgerForTest(ctx, t, "LED-049", "the enroller is the only credential "+
		"the core writes accounts with, so a skipped check is an unmeasured write path")
	provision(ctx, t, pg)

	assertAccepted := func(when string) {
		t.Helper()
		pool, err := pgxpool.New(ctx, pg.EnrollerDSN())
		if err != nil {
			t.Fatalf("pgxpool.New(enroller): %v", err)
		}
		defer pool.Close()
		report, err := api.AssertEnrollerScope(ctx, pool)
		if err != nil {
			t.Fatalf("%s: the role db-init.sh provisioned is not the one the core accepts: %v", when, err)
		}
		if report.Ledger.Role != deploytest.EnrollerRole {
			t.Errorf("%s: connected as %q, want %q", when, report.Ledger.Role, deploytest.EnrollerRole)
		}
	}
	assertAccepted("first run")

	// One GRANT too many: the shipped check must catch it and name it.
	if gerr := pg.PsqlAsOwner(ctx, "GRANT SELECT ON innsegl_auth.users TO "+deploytest.EnrollerRole); gerr != nil {
		t.Fatalf("widening the role: %v", gerr)
	}
	out, err := pg.RunInit(ctx, "verify-enroller-role.sh")
	if err == nil {
		t.Fatalf("verify-enroller-role.sh passed a role that can read users:\n%s", out)
	}
	if !strings.Contains(out, "read innsegl_auth.users") {
		t.Errorf("verify-enroller-role.sh did not name the widened grant:\n%s", out)
	}

	// The next update narrows it again.
	if out, err := pg.RunInit(ctx, "db-init.sh"); err != nil {
		t.Fatalf("db-init.sh second run: %v\n%s", err, out)
	}
	assertAccepted("second run")
}
