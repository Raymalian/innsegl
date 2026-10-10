// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"net/http"
	"testing"

	"innsegl.dev/innsegl/internal/event"
)

// API-035, resolving alerts: an alert of a run out of scope cannot be
// resolved, and the refusal is the one an unknown event id gets.
func TestAPI035AlertResolutionsAreScopedByTheirRun(t *testing.T) {
	h := newScopeHarness(t)
	drift, err := h.owner.Append(t.Context(), driftAlertFields("01a072b2-cdda-774e-a0e2-889ec5ac33fa",
		"scope-resolve-drift", "run-002", "spiffe://innsegl.dev/agent/fix-ci/jira-102/run-002"))
	if err != nil {
		t.Fatal(err)
	}
	id, ok := drift[event.FieldEventID].(string)
	if !ok {
		t.Fatalf("the appended alert has no event id: %v", drift)
	}
	const unknown = "01a072b2-cdda-774e-a0e2-000000000000"
	begin := func(eventID string) answer {
		return do(t, http.MethodPost, h.srv.URL+"/api/v1/alert-resolutions/begin",
			mustJSON(t, ResolveRequest{EventIDs: []string{eventID}, Reason: "checked"}), h.cookie)
	}

	h.as(inB)
	theirs, none := begin(id), begin(unknown)
	if theirs.status != http.StatusNotFound || none.status != http.StatusNotFound {
		t.Fatalf("another organisation's alert = %d, an unknown id = %d; want 404 for both: %s",
			theirs.status, none.status, theirs.body)
	}
	if !bytes.Equal(bytes.ReplaceAll(theirs.body, []byte(id), []byte(unknown)), none.body) {
		t.Errorf("the bodies differ:\n theirs %s\n none   %s", theirs.body, none.body)
	}

	h.as(inC)
	if a := begin(id); a.status != http.StatusOK {
		t.Errorf("C resolving its own run's alert: begin = %d: %s", a.status, a.body)
	}
}

// API-036, relatives: a run's parent and children out of scope are not
// named anywhere in what the run's own routes answer, except inside the
// run's own canonical events, which are the signed record and are never
// altered.
func TestAPI036ARelativeOutOfScopeIsNotNamed(t *testing.T) {
	h := newScopeHarness(t)
	child := func(runID, parent string) {
		f := event.Fields{
			event.FieldEventType:      event.EventTypeRunRegistered,
			event.FieldRunID:          runID,
			event.FieldSpiffeID:       "spiffe://innsegl.dev/agent/fix-ci/jira-9/" + runID,
			event.FieldSource:         event.SourceMCP,
			event.FieldAgentType:      "general-purpose",
			event.FieldTaskRef:        "JIRA-9",
			event.FieldRepo:           "github.com/innsegl/one",
			event.FieldBranch:         "main",
			event.FieldParentRunID:    parent,
			event.FieldIdempotencyKey: runID + "-register",
		}
		if _, err := h.owner.Append(t.Context(), f); err != nil {
			t.Fatal(err)
		}
	}
	child("run-kid-b", "run-002") // B's run under C's parent
	insertMapping(t, h.ownerDSN, "run-kid-b", machineRunner)
	child("run-kid-c", "run-001") // C's run under B's parent
	insertMapping(t, h.ownerDSN, "run-kid-c", machineOther)

	h.as(inB)
	for _, path := range []string{"/api/v1/runs/run-kid-b/record", "/api/v1/runs"} {
		a := get(t, h.srv.URL, path, h.cookie)
		if a.status != http.StatusOK {
			t.Fatalf("%s = %d: %s", path, a.status, a.body)
		}
		if bytes.Contains(a.body, []byte("run-002")) {
			t.Errorf("%s names C's run-002, the parent out of scope: %s", path, a.body)
		}
	}
	var d RunDetail
	decodeBody(t, get(t, h.srv.URL, "/api/v1/runs/run-kid-b", h.cookie), &d)
	if d.ParentRunID != "" {
		t.Errorf("the run detail answers parent %q, out of scope", d.ParentRunID)
	}
	a := get(t, h.srv.URL, "/api/v1/runs/run-001/record", h.cookie)
	if a.status != http.StatusOK {
		t.Fatalf("run-001's record = %d: %s", a.status, a.body)
	}
	if bytes.Contains(a.body, []byte("run-kid-c")) {
		t.Error("run-001's record names run-kid-c, a child out of scope")
	}
}
