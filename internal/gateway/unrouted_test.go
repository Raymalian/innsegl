// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// GW-020 (RM-319, #579): a machine's report of an unrouted session is kept
// once per session, with the newest activity any report carried.
func TestGW020TheUnroutedStoreKeepsOneRowPerSession(t *testing.T) {
	store, _ := newMigratedMappingStore(t)
	u := NewPostgresUnroutedStore(store.Pool())
	ctx := testCtx(t, 30*time.Second)
	t0 := time.Date(2026, 10, 11, 5, 0, 0, 0, time.UTC)

	for _, r := range []struct {
		inst, session string
		at            time.Time
	}{
		{"inst-1", "s-1", t0},
		{"inst-1", "s-1", t0.Add(time.Minute)},
		{"inst-1", "s-1", t0.Add(-time.Hour)}, // an older report never moves it back
		{"inst-2", "s-1", t0},
	} {
		if err := u.Report(ctx, r.inst, r.session, r.at); err != nil {
			t.Fatalf("Report %+v: %v", r, err)
		}
	}
	var n int
	var last time.Time
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM innsegl.unrouted_sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool().QueryRow(ctx, `SELECT last_activity_at FROM innsegl.unrouted_sessions
		WHERE installation_id = 'inst-1' AND session_id = 's-1'`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if n != 2 || !last.Equal(t0.Add(time.Minute)) {
		t.Fatalf("%d rows, inst-1's last activity %s; want 2 rows and %s", n, last, t0.Add(time.Minute))
	}
	if err := u.Report(ctx, "", "s-1", t0); err == nil {
		t.Fatal("a report with no installation was kept")
	}
}
