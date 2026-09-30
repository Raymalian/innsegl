// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http/httptest"
	"testing"
)

// TestRegisterRecordRoutesWiresThroughTheRealServer proves the seam this
// package exposes to cmd/innsegl/apiwiring.go: ConfigureRecordRoutes,
// called before NewServer, is what registerRecordRoutes reads when
// whatever calls it (server.go, another issue's own edit) does. This is
// the ONLY test in this package that builds a *Server and calls
// registerRecordRoutes directly; every other record test talks to a bare
// *recordServer, which needs no Server at all.
func TestRegisterRecordRoutesWiresThroughTheRealServer(t *testing.T) {
	f := newRecordFixture(t)

	restore := ConfigureRecordRoutes(RecordConfig{
		SnapshotDir: f.rs.cfg.root,
		GitPath:     f.rs.cfg.gitPath,
	})
	t.Cleanup(restore)

	srv, err := NewServer(ServerConfig{
		Store: f.store, Prover: f.rs.prover, LogDir: f.logDir,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.registerRecordRoutes()

	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)

	a := get(t, listening.URL, "/api/v1/runs/"+f.parentID+"/record")
	if a.status != 200 {
		t.Fatalf("GET record through the wired route: status %d: %s", a.status, a.body)
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
