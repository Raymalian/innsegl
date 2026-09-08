// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// TC-ALR — the alerts feed (RM-102, #167).
//
// #167: the query API serves a COUNT of `unattributed_signature_detected` and
// `ledger_drift_detected` events and no endpoint that lists them, so reading
// one today needs database access — the wrong shape for a system whose whole
// point is that the ledger and the public record can be read independently.
// These cases are the endpoint that closes that gap, and the recomputation of
// `open_alerts` #167's decision comment requires alongside it.

func driftAlertFields(subjectEventID, idempotencyKey, runID, spiffeID string) event.Fields {
	f := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldSource:         event.SourceReconciler,
		event.FieldIdempotencyKey: idempotencyKey,
		event.FieldSubjectEventID: subjectEventID,
		event.FieldReason:         "commit_recorded claims a Rekor entry that the log does not contain",
	}
	if runID != "" {
		f[event.FieldRunID] = runID
		f[event.FieldSpiffeID] = spiffeID
	}
	return f
}

func unattributedAlertFields(rekorUUID string, logIndex int64, idempotencyKey string) event.Fields {
	return event.Fields{
		event.FieldSchemaVersion:       event.SchemaVersion,
		event.FieldEventType:           event.EventTypeUnattributedSignatureDetected,
		event.FieldSource:              event.SourceReconciler,
		event.FieldIdempotencyKey:      idempotencyKey,
		event.FieldCertificateIdentity: "spiffe://innsegl.dev/agent/deadbeef/cafef00d/run-planted",
		event.FieldRekorEntryUUID:      rekorUUID,
		event.FieldRekorLogIndex:       logIndex,
	}
}

// seedAlerts writes n drift and n unattributed alert events, oldest first,
// and returns their event_ids in append order (drift, then unattributed,
// interleaved as written) so a test can identify what it seeded without a
// second read.
func seedAlerts(t *testing.T, owner *ledger.Store, n int) (drift, unattributed []event.Fields) {
	t.Helper()
	ctx := t.Context()
	for i := range n {
		d, err := owner.Append(ctx, driftAlertFields(
			"01a072b2-cdda-774e-a0e2-889ec5ac33fa",
			"alerts-test-drift-"+itoa(i),
			"run-alert-"+itoa(i),
			"spiffe://innsegl.dev/agent/fix-ci/jira-1/run-alert-"+itoa(i),
		))
		if err != nil {
			t.Fatalf("append drift alert %d: %v", i, err)
		}
		drift = append(drift, d)

		u, err := owner.Append(ctx, unattributedAlertFields(
			strings.Repeat("a", 63)+itoa(i%10), int64(100+i), "alerts-test-unattributed-"+itoa(i)))
		if err != nil {
			t.Fatalf("append unattributed alert %d: %v", i, err)
		}
		unattributed = append(unattributed, u)
	}
	return drift, unattributed
}

// ALR-002 — ListAlerts serves both alert types with the identifying fields
// #167 names, reads them out of the canonical body rather than inventing new
// storage, and — like ListRuns (API-003) — narrows in SQL rather than in Go.
func TestALR002ListAlertsServesBothTypesWithTheirIdentifyingFields(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	drift, unattributed := seedAlerts(t, owner, 4)
	s, counter := readStore(t, readerDSN)
	ctx := t.Context()

	t.Run("unfiltered, it serves every alert of both types", func(t *testing.T) {
		p, err := s.ListAlerts(ctx, AlertFilter{Limit: MaxPageSize})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if p.Total != 8 {
			t.Fatalf("Total = %d, want 8 (4 drift + 4 unattributed)", p.Total)
		}
		if len(p.Alerts) != 8 {
			t.Fatalf("len(Alerts) = %d, want 8", len(p.Alerts))
		}
		if p.DataAsOf.IsZero() {
			t.Error("AlertPage carries no data_as_of; FD §4.4 requires one")
		}
	})

	t.Run("a drift alert carries subject_event_id, run_id and reason", func(t *testing.T) {
		want := drift[0]
		p, err := s.ListAlerts(ctx, AlertFilter{EventType: event.EventTypeLedgerDriftDetected, Limit: MaxPageSize})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(p.Alerts) != 4 {
			t.Fatalf("filtered on drift: len(Alerts) = %d, want 4", len(p.Alerts))
		}
		var found *Alert
		for i := range p.Alerts {
			if p.Alerts[i].EventID == want[event.FieldEventID] {
				found = &p.Alerts[i]
			}
		}
		if found == nil {
			t.Fatalf("seeded drift event %v not found in the filtered page", want[event.FieldEventID])
		}
		if found.SubjectEventID != want[event.FieldSubjectEventID] {
			t.Errorf("SubjectEventID = %q, want %q", found.SubjectEventID, want[event.FieldSubjectEventID])
		}
		if found.Reason != want[event.FieldReason] {
			t.Errorf("Reason = %q, want %q", found.Reason, want[event.FieldReason])
		}
		if found.RunID != want[event.FieldRunID] {
			t.Errorf("RunID = %q, want %q", found.RunID, want[event.FieldRunID])
		}
		if found.CertificateIdentity != "" || found.RekorEntryUUID != "" {
			t.Errorf("a drift alert carries unattributed-only fields: %+v", found)
		}
	})

	t.Run("an unattributed alert carries certificate_identity, rekor_entry_uuid and rekor_log_index, and no run_id", func(t *testing.T) {
		want := unattributed[0]
		p, err := s.ListAlerts(ctx, AlertFilter{EventType: event.EventTypeUnattributedSignatureDetected, Limit: MaxPageSize})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		var found *Alert
		for i := range p.Alerts {
			if p.Alerts[i].EventID == want[event.FieldEventID] {
				found = &p.Alerts[i]
			}
		}
		if found == nil {
			t.Fatalf("seeded unattributed event %v not found in the filtered page", want[event.FieldEventID])
		}
		if found.CertificateIdentity != want[event.FieldCertificateIdentity] {
			t.Errorf("CertificateIdentity = %q, want %q", found.CertificateIdentity, want[event.FieldCertificateIdentity])
		}
		if found.RekorEntryUUID != want[event.FieldRekorEntryUUID] {
			t.Errorf("RekorEntryUUID = %q, want %q", found.RekorEntryUUID, want[event.FieldRekorEntryUUID])
		}
		if found.RekorLogIndex != want[event.FieldRekorLogIndex] {
			t.Errorf("RekorLogIndex = %d, want %d", found.RekorLogIndex, want[event.FieldRekorLogIndex])
		}
		if found.RunID != "" {
			t.Errorf("RunID = %q, want empty: doc 02 §3 omits run_id on a system-scope alert", found.RunID)
		}
		if found.SubjectEventID != "" || found.Reason != "" {
			t.Errorf("an unattributed alert carries drift-only fields: %+v", found)
		}
	})

	t.Run("an unknown event_type is refused", func(t *testing.T) {
		if _, err := s.ListAlerts(ctx, AlertFilter{EventType: "run_registered"}); err == nil {
			t.Error("ListAlerts accepted event_type=run_registered, which is not an alert type")
		}
	})

	t.Run("paging narrows in SQL, matching ListRuns' API-003 measurement", func(t *testing.T) {
		counter.reset()
		p, err := s.ListAlerts(ctx, AlertFilter{Limit: 3})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(p.Alerts) != 3 {
			t.Fatalf("len(Alerts) = %d, want 3", len(p.Alerts))
		}
		if p.NextCursor == "" {
			t.Fatal("a page equal to the limit carries no next_cursor")
		}
		if counter.queryCount() == 0 {
			t.Fatal("the tracer observed no queries")
		}
		if got := counter.maxRows(); got > 3 {
			t.Errorf("a query returned %d rows for a page of 3: the narrowing is not in SQL", got)
		}
	})
}

// ALR-004 — open_alerts is recomputed as the count of alert events with NO
// resolution row, per #167's decision: "'Open' becomes derived, not stored —
// alert events with no resolution row." Resolving one drops the count by
// exactly one; the resolved alert stays in the list, and stays in
// innsegl.events, unchanged.
func TestALR004OpenAlertsExcludesResolvedAlerts(t *testing.T) {
	owner, _, readerDSN := migrated(t)
	drift, unattributed := seedAlerts(t, owner, 3)
	s, _ := readStore(t, readerDSN)
	ctx := t.Context()

	before, err := s.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if before.OpenAlerts != 6 {
		t.Fatalf("OpenAlerts = %d before any resolution, want 6", before.OpenAlerts)
	}

	target := drift[0]
	eventID := memberString(t, target, event.FieldEventID)
	if _, rerr := owner.ResolveAlert(ctx, eventID, "kody@example.com", "sigstore reset under a surviving ledger"); rerr != nil {
		t.Fatalf("ResolveAlert: %v", rerr)
	}

	after, err := s.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if after.OpenAlerts != 5 {
		t.Errorf("OpenAlerts = %d after resolving one, want 5", after.OpenAlerts)
	}

	// The resolved alert is still an alert: it stays in the list, carries its
	// resolution, and innsegl.events itself was never asked to change.
	p, err := s.ListAlerts(ctx, AlertFilter{Limit: MaxPageSize})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if p.Total != 6 {
		t.Errorf("ListAlerts Total = %d after a resolution, want 6: a resolved alert is "+
			"still an alert (#167: the event is permanent and unchanged)", p.Total)
	}
	var found *Alert
	for i := range p.Alerts {
		if p.Alerts[i].EventID == eventID {
			found = &p.Alerts[i]
		}
	}
	if found == nil {
		t.Fatalf("resolved alert %s is missing from the list entirely", eventID)
	}
	if !found.Resolved {
		t.Error("Resolved = false for an alert with a resolution row")
	}
	if found.ResolvedBy != "kody@example.com" {
		t.Errorf("ResolvedBy = %q", found.ResolvedBy)
	}
	if found.ResolvedAt.IsZero() {
		t.Error("ResolvedAt is zero on a resolved alert")
	}

	// The other five, including the untouched unattributed alerts, still read
	// as unresolved.
	unresolvedSeen := 0
	for _, a := range p.Alerts {
		if !a.Resolved {
			unresolvedSeen++
		}
	}
	if unresolvedSeen != 5 {
		t.Errorf("%d alerts read as unresolved, want 5", unresolvedSeen)
	}
	_ = unattributed
}

// ALR-003 — the HTTP route: filtering, pagination, and a bad event_type
// refused the same way an unknown run status is (400, not 500 or a silent
// empty page).
func TestALR003AlertsRoute(t *testing.T) {
	listening, _ := testServerWithAlerts(t)

	t.Run("serves a page of alerts", func(t *testing.T) {
		a := get(t, listening.URL, "/api/v1/alerts")
		if a.status != http.StatusOK {
			t.Fatalf("GET /api/v1/alerts = %d, want 200: %s", a.status, a.body)
		}
		var page AlertPage
		decodeBody(t, a, &page)
		if page.Total == 0 {
			t.Fatal("Total = 0; the fixture seeded alerts")
		}
	})

	t.Run("filters by event_type", func(t *testing.T) {
		a := get(t, listening.URL, "/api/v1/alerts?event_type=ledger_drift_detected")
		if a.status != http.StatusOK {
			t.Fatalf("GET .../alerts?event_type=ledger_drift_detected = %d: %s", a.status, a.body)
		}
		var page AlertPage
		decodeBody(t, a, &page)
		for _, al := range page.Alerts {
			if al.EventType != "ledger_drift_detected" {
				t.Errorf("filtered page carries a %s alert", al.EventType)
			}
		}
	})

	t.Run("an unrecognised event_type is a 400", func(t *testing.T) {
		a := get(t, listening.URL, "/api/v1/alerts?event_type=run_registered")
		if a.status != http.StatusBadRequest {
			t.Fatalf("GET .../alerts?event_type=run_registered = %d, want 400: %s", a.status, a.body)
		}
	})

	t.Run("a non-GET method is refused before it reaches the handler", func(t *testing.T) {
		a := do(t, http.MethodPost, listening.URL+"/api/v1/alerts", "")
		if a.status != http.StatusMethodNotAllowed {
			t.Fatalf("POST /api/v1/alerts = %d, want 405: %s", a.status, a.body)
		}
	})

	t.Run("limit is capped like every other page", func(t *testing.T) {
		a := get(t, listening.URL, "/api/v1/alerts?limit=100000")
		if a.status != http.StatusOK {
			t.Fatalf("GET .../alerts?limit=100000 = %d: %s", a.status, a.body)
		}
		var page AlertPage
		decodeBody(t, a, &page)
		if page.Limit != MaxPageSize {
			t.Errorf("Limit = %d, want the cap %d", page.Limit, MaxPageSize)
		}
	})
}

// testServerWithAlerts is testServer plus six seeded alert events, for the
// HTTP-layer cases that only need alerts to exist and do not need to name
// individual event_ids.
func testServerWithAlerts(t *testing.T) (*httptest.Server, *proofScenario) {
	t.Helper()
	owner, _, readerDSN := migrated(t)
	seedAlerts(t, owner, 3)
	store, _ := readStore(t, readerDSN)

	s := newProofScenario(t, proofOptions{})
	srv, err := NewServer(ServerConfig{Store: store, Prover: s.prover(t)})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listening := httptest.NewServer(srv)
	t.Cleanup(listening.Close)
	return listening, s
}

// memberString reads a string member of an event.Fields result, failing
// rather than swallowing a bad type assertion (matches internal/ledger's
// helper of the same name).
func memberString(t *testing.T, f event.Fields, name string) string {
	t.Helper()
	v, ok := f[name].(string)
	if !ok {
		t.Fatalf("member %q is %T, want string", name, f[name])
	}
	return v
}
