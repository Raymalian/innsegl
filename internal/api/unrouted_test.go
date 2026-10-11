// SPDX-License-Identifier: Apache-2.0

package api

import (
	"slices"
	"testing"
	"time"
)

// API-039 (RM-319, #579): the overview lists the sessions machines reported
// as bypassing innsegl, newest activity first, scoped to the viewer's
// machines like every other read; none is an empty list, never null.
func TestAPI039TheOverviewListsUnroutedSessionsInScope(t *testing.T) {
	h := newScopeHarness(t)
	c, ctx := ownerConnAPI(t, h.ownerDSN)

	h.as(inA)
	var empty Overview
	decodeBody(t, get(t, h.srv.URL, "/api/v1/overview", h.cookie), &empty)
	if empty.UnroutedSessions == nil || len(empty.UnroutedSessions) != 0 {
		t.Fatalf("with none reported the overview lists %#v; want an empty list", empty.UnroutedSessions)
	}

	t0 := time.Date(2026, 10, 11, 5, 0, 0, 0, time.UTC)
	for _, r := range []struct {
		machine, session string
		at               time.Time
	}{
		{machineLaptop, "s-laptop-old", t0},
		{machineLaptop, "s-laptop-new", t0.Add(time.Hour)},
		{machineOther, "s-other", t0.Add(2 * time.Hour)},
	} {
		if _, err := c.Exec(ctx, `INSERT INTO innsegl.unrouted_sessions (installation_id, session_id, last_activity_at)
			VALUES ($1, $2, $3)`, r.machine, r.session, r.at); err != nil {
			t.Fatal(err)
		}
	}

	sessions := func() []UnroutedSession {
		t.Helper()
		var o Overview
		decodeBody(t, get(t, h.srv.URL, "/api/v1/overview", h.cookie), &o)
		return o.UnroutedSessions
	}

	h.as(inA)
	got := sessions()
	ids := make([]string, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.SessionID)
		if s.InstallationID != machineLaptop || s.LastActivityAt.IsZero() || s.FirstReportedAt.IsZero() {
			t.Errorf("A sees %+v; want only the laptop's sessions, with their times", s)
		}
	}
	if want := []string{"s-laptop-new", "s-laptop-old"}; !slices.Equal(ids, want) {
		t.Errorf("A sees %v, want %v (newest first)", ids, want)
	}

	h.as(inC)
	if got := sessions(); len(got) != 1 || got[0].SessionID != "s-other" {
		t.Errorf("C sees %+v, want only its own machine's session", got)
	}
	h.as(inB)
	if got := sessions(); len(got) != 0 {
		t.Errorf("B, whose machine reported nothing, sees %+v", got)
	}
}
