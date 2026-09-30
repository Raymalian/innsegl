// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegisterRecordRoutesWiresThroughTheRealServer proves the record and
// diff routes are wired by NewServer itself, with ConfigureRecordRoutes'
// settings, and sit behind ADR-0062's gate like every other read route: no
// session, no record; a signed-in session, the record.
func TestRegisterRecordRoutesWiresThroughTheRealServer(t *testing.T) {
	f := newRecordFixture(t)

	restore := ConfigureRecordRoutes(RecordConfig{
		SnapshotDir: f.rs.cfg.root,
		GitPath:     f.rs.cfg.gitPath,
	})
	t.Cleanup(restore)

	authStore := testAuthStore(t)
	srv, err := NewServer(ServerConfig{
		Store: f.store, Prover: f.rs.prover, LogDir: f.logDir,
		AuthStore: authStore, WebAuthn: testWebAuthnConfig,
		ManagedSettingsPath: writeManagedSettings(t, denyingManagedSettingsJSON),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)

	if a := get(t, listening.URL, "/api/v1/runs/"+f.parentID+"/record"); a.status != http.StatusUnauthorized {
		t.Fatalf("GET record with no session: status %d, want 401: %s", a.status, a.body)
	}
	if a := get(t, listening.URL, "/api/v1/runs/"+f.parentID+"/steps/1/diff"); a.status != http.StatusUnauthorized {
		t.Fatalf("GET diff with no session: status %d, want 401: %s", a.status, a.body)
	}

	cookie := signInTestUser(t, listening.URL, authStore)
	a := get(t, listening.URL, "/api/v1/runs/"+f.parentID+"/record", cookie)
	if a.status != http.StatusOK {
		t.Fatalf("GET record signed in: status %d: %s", a.status, a.body)
	}
	var rec RunRecord
	decodeBody(t, a, &rec)
	if rec.Run.RunID != f.parentID {
		t.Errorf("Run.RunID = %q, want %q", rec.Run.RunID, f.parentID)
	}
	if len(rec.Steps) != 4 {
		t.Errorf("got %d steps through the wired route, want 4", len(rec.Steps))
	}
}

// TestHandleRunRecordRejectsAMalformedRunID covers runIDFromPath's own
// refusal: a run id reaching this handler is validated against doc 02 §5's
// grammar before it becomes a SQL parameter or a directory name.
func TestHandleRunRecordRejectsAMalformedRunID(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)

	for _, bad := range []string{"UPPERCASE-not-allowed", "under_score", "-leading-dash"} {
		a := get(t, srv.URL, "/api/v1/runs/"+bad+"/record")
		if a.status != 400 {
			t.Errorf("run_id %q: status %d, want 400: %s", bad, a.status, a.body)
		}
	}
}

// TestHandleStepDiffRejectsAMalformedStepNumber.
func TestHandleStepDiffRejectsAMalformedStepNumber(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)

	for _, bad := range []string{"0", "-1", "not-a-number"} {
		a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/"+bad+"/diff")
		if a.status != 400 {
			t.Errorf("step %q: status %d, want 400: %s", bad, a.status, a.body)
		}
	}
}
