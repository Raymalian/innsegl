// SPDX-License-Identifier: Apache-2.0

package trusthistory

import (
	"testing"
	"time"
)

func TestWarningForTheTwoThresholds(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		notAfter time.Time
		want     Warning
	}{
		{now.AddDate(10, 0, 0), WarningNone},
		{now.AddDate(1, 0, 1), WarningNone},
		{now.AddDate(1, 0, 0), WarningYear},
		{now.AddDate(0, 0, 91), WarningYear},
		{now.AddDate(0, 0, 90), Warning90Days},
		{now.Add(time.Hour), Warning90Days},
		{now, WarningExpired},
		{now.Add(-time.Hour), WarningExpired},
	}
	for _, c := range cases {
		if got := WarningFor(c.notAfter, now); got != c.want {
			t.Errorf("WarningFor(%s) = %q, want %q", c.notAfter.Format(time.DateOnly), got, c.want)
		}
	}
}

func TestExpiriesNameEveryCAInUse(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	h := New()
	oldRoot := caPEM(t, "old", day1.AddDate(-1, 0, 0), now.AddDate(0, 0, 30))
	newRoot := caPEM(t, "new", day1, time.Date(2036, 9, 13, 0, 0, 0, 0, time.UTC))
	for _, r := range []struct {
		kind Kind
		pem  []byte
	}{
		{KindFulcioRoot, oldRoot},
		{KindFulcioRoot, newRoot},
		{KindTransparencyLog, logKeyPEM(t)},
		{KindSPIREUpstreamCA, caPEM(t, "spire", day1, time.Date(2036, 9, 13, 0, 0, 0, 0, time.UTC))},
		{KindGatewayCA, caPEM(t, "gw", day1, now.AddDate(0, 0, 60))},
	} {
		if _, err := h.Record(r.kind, r.pem, day1); err != nil {
			t.Fatal(err)
		}
	}
	got := Expiries(h, now)
	// One per CA kind, the current one; the retired-in-practice old root no
	// longer issues and is not a CA in use; the log key has no expiry.
	if len(got) != 3 {
		t.Fatalf("Expiries = %+v, want three", got)
	}
	byKind := map[Kind]Expiry{}
	for _, e := range got {
		byKind[e.Kind] = e
	}
	if e := byKind[KindFulcioRoot]; e.Warning != WarningNone || e.NotAfter.Year() != 2036 {
		t.Errorf("fulcio root = %+v, want the current root, no warning", e)
	}
	if e := byKind[KindGatewayCA]; e.Warning != Warning90Days {
		t.Errorf("gateway CA = %+v, want a 90-day warning", e)
	}
	if byKind[KindSPIREUpstreamCA].Name == "" {
		t.Error("the SPIRE upstream CA has no name to show")
	}
	if Expiries(nil, now) != nil {
		t.Error("a nil history has expiries")
	}
}
