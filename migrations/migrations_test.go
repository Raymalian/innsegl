// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strings"
	"testing"
)

// TestAllReturnsEveryMigrationInOrder holds the embedded set to the two rules
// the runner depends on: every file is named NNNN_name.sql, and versions are
// unique and ascending. A file the runner cannot see is a schema change that
// silently did not happen.
func TestAllReturnsEveryMigrationInOrder(t *testing.T) {
	t.Parallel()

	all, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("no migrations are embedded")
	}

	seen := make(map[string]bool, len(all))
	previous := ""
	for _, m := range all {
		if seen[m.Version] {
			t.Fatalf("version %s appears twice", m.Version)
		}
		seen[m.Version] = true
		if m.Version <= previous {
			t.Fatalf("version %s follows %s; migrations are applied in name order", m.Version, previous)
		}
		previous = m.Version
		if !strings.HasPrefix(m.Name, m.Version+"_") || !strings.HasSuffix(m.Name, ".sql") {
			t.Fatalf("%q does not carry its version %s", m.Name, m.Version)
		}
		if strings.TrimSpace(m.SQL) == "" {
			t.Fatalf("%s is empty", m.Name)
		}
		if !strings.Contains(m.SQL, "SPDX-License-Identifier: Apache-2.0") {
			t.Fatalf("%s carries no SPDX header", m.Name)
		}
	}

	if FS() == nil {
		t.Fatal("FS() exposes no filesystem")
	}
}

// TestFirstMigrationCarriesTheAppendOnlyGuards is a spot check that the
// schema's refusals are in the migration rather than only in a comment. The
// behavioural proof is in internal/ledger, against a real Postgres; this is
// the cheap guard that catches a deletion.
func TestFirstMigrationCarriesTheAppendOnlyGuards(t *testing.T) {
	t.Parallel()

	all, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	joined := ""
	for _, m := range all {
		joined += m.SQL
	}
	for _, want := range []string{
		"BEFORE UPDATE OR DELETE OR TRUNCATE ON innsegl.events",
		"BEFORE INSERT ON innsegl.events",
		"ENABLE ALWAYS TRIGGER",
		"REVOKE UPDATE, DELETE, TRUNCATE ON innsegl.events FROM PUBLIC",
		"ERRCODE = 'IN001'",
		"ERRCODE = 'IN002'",
		"prev_event_hash text NOT NULL UNIQUE",
		"chain_position  bigint PRIMARY KEY",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("no migration contains %q; the append-only schema is not what it claims", want)
		}
	}
}
