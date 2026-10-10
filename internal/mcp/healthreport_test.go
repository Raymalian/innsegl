// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// OPS-172 (proposed for doc 07), the health half — a scheduled control's
// result is on /readyz, as a report and never as a reason to be unready.
//
// doc 05 §2 makes the scheduled WORM canary a required control whose absence
// must fail the deployment's readiness REPORTING. It must not fail readiness
// itself: a failed canary is a finding about the bucket, and a replica that
// stopped taking traffic over it would stop recording agents while the
// bucket was being looked at.
func TestOPS172ReadinessCarriesReportsThatNeverGateIt(t *testing.T) {
	h := healthWithFakes(t, HealthConfig{Reports: func() []HealthReport {
		return []HealthReport{{Name: "worm canary", OK: false, Detail: "failed: version_delete_refused"}}
	}})
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, ReadyPath, http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("a failed report made /readyz answer %d; it must stay a report", rec.Code)
	}
	var wire struct {
		Ready   bool `json:"ready"`
		Reports []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body, err)
	}
	if !wire.Ready {
		t.Fatal("ready is false over a report")
	}
	if len(wire.Reports) != 1 || wire.Reports[0].Name != "worm canary" || wire.Reports[0].OK ||
		wire.Reports[0].Detail != "failed: version_delete_refused" {
		t.Fatalf("reports = %+v", wire.Reports)
	}

	// No reports configured: the field is absent, as before.
	plain := healthWithFakes(t, HealthConfig{})
	body, err := json.Marshal(plain.Ready(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["reports"]; ok {
		t.Fatalf("a health with no reports published a reports field: %s", body)
	}
}
