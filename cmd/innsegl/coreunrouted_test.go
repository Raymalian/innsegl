// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/client"
	"innsegl.dev/innsegl/internal/gateway"
)

type fakeUnroutedStore struct {
	got []string
	err error
}

func (f *fakeUnroutedStore) Report(_ context.Context, installation, session string, at time.Time) error {
	if f.err != nil {
		return f.err
	}
	f.got = append(f.got, installation+"/"+session+"@"+at.UTC().Format(time.RFC3339))
	return nil
}

// GW-020 (RM-319, #579): the core takes a report of an unrouted session only
// from an enrolled machine, keeps it under that machine, and refuses a
// malformed one.
func TestGW020TheCoreTakesUnroutedReportsFromEnrolledMachinesOnly(t *testing.T) {
	store := &fakeUnroutedStore{}
	h := unroutedHandler(store, newServeLog(&bytes.Buffer{}))
	post := func(installation, method, body string) int {
		ctx := t.Context()
		if installation != "" {
			ctx = gateway.WithInstallation(ctx, installation)
		}
		req := httptest.NewRequestWithContext(ctx, method, client.UnroutedPath, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	good := `{"session_id":"s-1","last_activity_at":"2026-10-11T05:01:00Z"}`

	if code := post("", http.MethodPost, good); code != http.StatusUnauthorized {
		t.Fatalf("a report with no verified machine = %d, want 401", code)
	}
	if code := post("inst-1", http.MethodGet, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", code)
	}
	for _, bad := range []string{
		`not json`,
		`{"last_activity_at":"2026-10-11T05:01:00Z"}`,
		`{"session_id":"s-1"}`,
		`{"session_id":"` + strings.Repeat("x", 300) + `","last_activity_at":"2026-10-11T05:01:00Z"}`,
		`{"session_id":"s 1","last_activity_at":"2026-10-11T05:01:00Z"}`,
		`{"session_id":"s-1","last_activity_at":"2999-01-01T00:00:00Z"}`,
	} {
		if code := post("inst-1", http.MethodPost, bad); code != http.StatusBadRequest {
			t.Errorf("malformed report %s = %d, want 400", bad, code)
		}
	}
	if len(store.got) != 0 {
		t.Fatalf("refused reports were kept: %v", store.got)
	}
	if code := post("inst-1", http.MethodPost, good); code != http.StatusNoContent {
		t.Fatalf("a good report = %d, want 204", code)
	}
	if len(store.got) != 1 || store.got[0] != "inst-1/s-1@2026-10-11T05:01:00Z" {
		t.Fatalf("kept %v; want the report under inst-1", store.got)
	}
	store.err = errors.New("ledger down")
	if code := post("inst-1", http.MethodPost, good); code != http.StatusServiceUnavailable {
		t.Fatalf("a store failure = %d, want 503 so the client tells it again", code)
	}
}
