// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
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

// TestRunRecordOfABareRunEncodesEmptyListsNotNull — #435. A run with no
// recorded steps (every run from before the gateway) was served with
// "steps": null and "replies": null, and the run page crashed on .find of
// null, leaving a blank screen. The contract (web/src/views/run-page/
// types.ts) types every list as an array, so every list is [] when empty.
func TestRunRecordOfABareRunEncodesEmptyListsNotNull(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)

	a := get(t, srv.URL, "/api/v1/runs/run-e19-bare/record")
	if a.status != http.StatusOK {
		t.Fatalf("GET bare run record: status %d: %s", a.status, a.body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(a.body, &raw); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, list := range []string{"replies", "steps", "files", "commits"} {
		if got := string(raw[list]); got != "[]" {
			t.Errorf("%q = %s, want []", list, got)
		}
	}
	var tree struct {
		Nodes json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(raw["tree"], &tree); err != nil || string(tree.Nodes) == "null" {
		t.Errorf("tree.nodes = %s, want a list", tree.Nodes)
	}
}

// TestClipStepTextCapsLongTextOnARuneBoundary — #440. The run record carried
// every step's full input and output: 1.4 MB for a 145-step run, and tens of
// megabytes for a long session, which froze the browser rendering it.
func TestClipStepTextCapsLongTextOnARuneBoundary(t *testing.T) {
	short := "hello"
	if got, clipped := clipStepText(short); got != short || clipped {
		t.Errorf("clipStepText(short) = %q, %v; want unchanged, false", got, clipped)
	}
	long := strings.Repeat("é", stepTextCap) // two bytes each: twice the cap
	got, clipped := clipStepText(long)
	if !clipped || len(got) > stepTextCap || !utf8.ValidString(got) {
		t.Errorf("clipStepText(long) = %d bytes, clipped %v, valid %v; want ≤ %d valid bytes, clipped",
			len(got), clipped, utf8.ValidString(got), stepTextCap)
	}
}

// TestStepRouteServesOneStepInFull — #440: a clipped step's full text is one
// request away.
func TestStepRouteServesOneStepInFull(t *testing.T) {
	f := newRecordFixture(t)
	srv := newRecordTestServer(t, f.rs)

	a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/1")
	if a.status != http.StatusOK {
		t.Fatalf("GET step 1: status %d: %s", a.status, a.body)
	}
	var step RecordStep
	decodeBody(t, a, &step)
	if step.N != 1 || step.Clipped {
		t.Errorf("step = n %d clipped %v; want step 1, not clipped", step.N, step.Clipped)
	}
	if a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/99"); a.status != http.StatusNotFound {
		t.Errorf("GET step 99: status %d, want 404", a.status)
	}
	if a := get(t, srv.URL, "/api/v1/runs/"+f.parentID+"/steps/0"); a.status != http.StatusBadRequest {
		t.Errorf("GET step 0: status %d, want 400", a.status)
	}
}

// TestRunRecordLooksUpTheParentSnapshotOnce — #440. Measured on 2026-10-01:
// for a run with no snapshots of its own, every step re-ran the same parent
// lookup over the parent's whole tool_call history: 145 queries, 1.2 s of a
// 1.35 s request. The answer depends only on the parent and the run's own
// registration, so it is looked up at most once per record.
func TestRunRecordLooksUpTheParentSnapshotOnce(t *testing.T) {
	f := newRecordFixture(t)
	f.store.parentSnapshotLookups.Store(0)
	rec, err := f.rs.buildRunRecord(context.Background(), "run-e19-hookchild")
	if err != nil {
		t.Fatalf("buildRunRecord: %v", err)
	}
	if len(rec.Steps) != 3 {
		t.Fatalf("got %d steps, want 3", len(rec.Steps))
	}
	if got := f.store.parentSnapshotLookups.Load(); got > 1 {
		t.Errorf("parent snapshot looked up %d times for one record, want at most 1", got)
	}
}
