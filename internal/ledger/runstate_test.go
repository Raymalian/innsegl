// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"testing"
	"time"
)

// REC-018 (proposed for doc 07; doc 07 is not modified here) — the Go half.
//
// This file asserts the rule itself over every combination of the facts it
// reads. REC-018's other half — that the SQL rendering of the same rule, driven
// by the real query API, and the reconciler's reading of this one agree about
// the same runs on a real chain — is internal/api/agreement_test.go, which
// needs a database and both components. Neither half is sufficient alone: this
// one cannot see a divergence between the two renderings, and that one cannot
// enumerate combinations a fixture does not happen to contain.

// The instants every case below is built from. Fixed rather than relative to
// time.Now so that a case says what it means and cannot flake.
var (
	stateNow        = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	stateRegistered = stateNow.Add(-72 * time.Hour)
	stateOld        = stateNow.Add(-48 * time.Hour)
	stateMiddle     = stateNow.Add(-24 * time.Hour)
	stateRecent     = stateNow.Add(-1 * time.Hour)
)

// stateHorizon is longer than anything in the fixture is old, so a withdrawal
// is inside it unless a case says otherwise.
const stateHorizon = 30 * 24 * time.Hour

func TestREC018TheRuleOverEveryCombinationOfTheFacts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		facts   RunFacts
		horizon time.Duration
		want    string
	}{
		{
			name:    "registered and nothing else",
			facts:   RunFacts{RegisteredAt: stateRegistered, LastActivityAt: stateRegistered},
			horizon: stateHorizon,
			want:    RunActive,
		},
		{
			name: "working: activity, never withdrawn",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateRecent,
			},
			horizon: stateHorizon,
			want:    RunActive,
		},
		{
			name: "withdrawn and quiet since, inside the horizon",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateRegistered,
				WithdrawnAt: stateMiddle,
			},
			horizon: stateHorizon,
			want:    RunLapsed,
		},
		{
			name: "withdrawn and quiet since, past the horizon",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateRegistered,
				WithdrawnAt: stateMiddle,
			},
			horizon: time.Hour,
			want:    RunAbandoned,
		},
		{
			name: "withdrawn, with no horizon at all",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateRegistered,
				WithdrawnAt: stateOld,
			},
			horizon: 0,
			want:    RunLapsed,
		},
		{
			name: "restored: activity newer than the withdrawal",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateMiddle,
				LastActivityAt: stateRecent,
			},
			horizon: stateHorizon,
			want:    RunActive,
		},
		{
			name: "restored, and the withdrawal it was restored from is ancient",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateOld,
				LastActivityAt: stateRecent,
			},
			// A horizon a withdrawal that no longer stands is well outside.
			// It decides nothing: only a STANDING withdrawal is measured.
			horizon: time.Hour,
			want:    RunActive,
		},
		{
			name: "lapsed again: a second withdrawal after the activity",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateMiddle,
				WithdrawnAt: stateRecent,
			},
			horizon: stateHorizon,
			want:    RunLapsed,
		},
		{
			name: "withdrawn at the same instant as the activity",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateMiddle,
				WithdrawnAt: stateMiddle,
			},
			// A tie is a withdrawal that stands: the reaper acts on silence it
			// has already observed, so an event sharing its instant is not
			// news. The SQL says the same with `last_activity_at <=
			// withdrawn_at`, and a tie reading the two ways would be exactly
			// the drift REC-018 exists to catch.
			horizon: stateHorizon,
			want:    RunLapsed,
		},
		{
			name:    "retired",
			facts:   RunFacts{RegisteredAt: stateRegistered, Retired: true, RetiredAt: stateMiddle},
			horizon: stateHorizon,
			want:    RunRetired,
		},
		{
			name: "retired, then a straggling call",
			facts: RunFacts{
				RegisteredAt: stateRegistered, Retired: true, RetiredAt: stateMiddle,
				LastActivityAt: stateRecent,
			},
			horizon: stateHorizon,
			want:    RunRetired,
		},
		{
			name: "withdrawn, then retired",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateOld,
				Retired: true, RetiredAt: stateMiddle,
			},
			horizon: stateHorizon,
			want:    RunRetired,
		},
		{
			name: "retired, then withdrawn by a reaper that had not caught up",
			facts: RunFacts{
				RegisteredAt: stateRegistered, Retired: true, RetiredAt: stateOld,
				WithdrawnAt: stateMiddle,
			},
			horizon: stateHorizon,
			want:    RunRetired,
		},
		{
			name: "restored, worked, and then retired",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateOld,
				LastActivityAt: stateMiddle, Retired: true, RetiredAt: stateRecent,
			},
			horizon: stateHorizon,
			want:    RunRetired,
		},
		{
			name: "retired, with an instant nothing could read",
			facts: RunFacts{
				RegisteredAt: stateRegistered, Retired: true,
				LastActivityAt: stateRecent,
			},
			// Retired decides; RetiredAt only dates. A retirement this reader
			// could not date is still a retirement, which is what lets the SQL
			// derive it as bool_or over the event type and never need a
			// timestamp at all.
			horizon: stateHorizon,
			want:    RunRetired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RunStateOf(tc.facts, stateNow, tc.horizon); got != tc.want {
				t.Errorf("RunStateOf(%+v, horizon %s) = %q, want %q",
					tc.facts, tc.horizon, got, tc.want)
			}
		})
	}
}

// TestTheStateRestsOnAFactItCanName: whatever the rule concludes, DecidedAt
// names the recorded instant it concluded from.
//
// The reconciler ages a run against that instant before it accuses anyone
// (internal/spire, Config.MinAge), so a DecidedAt that pointed at the wrong
// fact would be a control waiting out the wrong window — silent about a real
// orphan, or loud about a run that spoke a second ago.
func TestTheStateRestsOnAFactItCanName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts RunFacts
		want  time.Time
	}{
		{
			name:  "an active run is dated by its registration",
			facts: RunFacts{RegisteredAt: stateRegistered},
			want:  stateRegistered,
		},
		{
			name: "an active run that has worked is dated by the work",
			facts: RunFacts{
				RegisteredAt: stateRegistered, LastActivityAt: stateRecent,
			},
			want: stateRecent,
		},
		{
			name: "a restored run is dated by the activity that overtook the withdrawal",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateMiddle,
				LastActivityAt: stateRecent,
			},
			want: stateRecent,
		},
		{
			name: "a lapsed run is dated by the withdrawal that stands",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateMiddle,
			},
			want: stateMiddle,
		},
		{
			name: "a retired run is dated by the retirement",
			facts: RunFacts{
				RegisteredAt: stateRegistered, WithdrawnAt: stateOld,
				LastActivityAt: stateRecent, Retired: true, RetiredAt: stateMiddle,
			},
			want: stateMiddle,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.facts.DecidedAt(); !got.Equal(tc.want) {
				t.Errorf("DecidedAt() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestTheHorizonIsOneNumberReadFromOneVariable.
//
// Every component that has an opinion about abandonment reads it here. The
// three refusals below are the ones that must NOT quietly select "no horizon":
// zero means a withdrawn run stays restorable until something ends it, and a
// typo arriving at that setting is a deployment that never abandons anything
// and never says so.
func TestTheHorizonIsOneNumberReadFromOneVariable(t *testing.T) {
	for _, tc := range []struct {
		set  string
		want time.Duration
	}{
		{set: "", want: DefaultRestoreHorizon},
		{set: "not-a-duration", want: DefaultRestoreHorizon},
		{set: "-1h", want: DefaultRestoreHorizon},
		{set: "0", want: 0},
		{set: "48h", want: 48 * time.Hour},
	} {
		t.Run("INNSEGL_ABANDON_AFTER="+tc.set, func(t *testing.T) {
			t.Setenv(EnvRestoreHorizon, tc.set)
			if got := RestoreHorizonFromEnv(); got != tc.want {
				t.Errorf("RestoreHorizonFromEnv() = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNoHorizonMeansNoCutoff: AbandonedBefore returns nothing to compare
// against when the deployment set no horizon, which is how "nothing is ever
// abandoned" reaches both renderings as an absent value rather than as a
// sentinel instant somebody has to remember.
func TestNoHorizonMeansNoCutoff(t *testing.T) {
	for _, horizon := range []time.Duration{0, -time.Hour} {
		if got := AbandonedBefore(horizon, stateNow); got != nil {
			t.Errorf("AbandonedBefore(%s) = %s, want nil", horizon, got)
		}
	}
	got := AbandonedBefore(24*time.Hour, stateNow)
	if got == nil {
		t.Fatal("AbandonedBefore(24h) = nil; a horizon a deployment set must produce a cutoff")
	}
	if want := stateNow.Add(-24 * time.Hour); !got.Equal(want) {
		t.Errorf("AbandonedBefore(24h) = %s, want %s", got, want)
	}
}
