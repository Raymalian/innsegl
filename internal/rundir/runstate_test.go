// SPDX-License-Identifier: Apache-2.0

package rundir

import (
	"context"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/mcp"
)

// REC-018, the MCP's side (proposed for doc 07; doc 07 is not modified here).
//
//	The shipped run directory, over a chain holding a withdrawal and the
//	activity that followed it
//	→ mcp.CredentialRun.State reads the same four words the reconciler and
//	  the query API read, from the same rule
//	→ IP §6.10
//
// # Why this is here and not in internal/mcp
//
// `CredentialRun.State` can only be right if `CredentialRun.LastActivityAt` is
// right, and the only thing that fills that in is this package: the directory
// is what reads a run's events off the chain. A case built on a hand-made
// CredentialRun would assert the arithmetic of a struct literal. This one
// drives the SHIPPED directory over the chain it really reads, and then asks
// the MCP's own view of the run what state it is in.
//
// The states themselves are asserted against internal/ledger's constants
// rather than against strings spelled here: a fourth spelling of the same four
// words is a fourth thing that can drift.

// stateHorizon is longer than the gap between any two instants below, so a
// withdrawal is inside it unless a case shortens it.
const stateHorizon = 30 * 24 * time.Hour

const (
	stateRegisteredTS = "2026-09-01T09:00:00.000Z"
	stateLapseTS      = "2026-09-02T09:00:00.000Z"
	stateWorkedTS     = "2026-09-03T09:00:00.000Z"
	stateSecondLapse  = "2026-09-04T09:00:00.000Z"
	stateRetiredTS    = "2026-09-05T09:00:00.000Z"
	stateNowTS        = "2026-09-06T09:00:00.000Z"
)

func TestREC018TheMCPReadsARunsStateFromTheOneRule(t *testing.T) {
	now := mustParse(t, stateNowTS)

	for _, tc := range []struct {
		name    string
		chain   []event.Fields
		horizon time.Duration
		want    string
	}{
		{
			name:    "registered and working",
			chain:   []event.Fields{registered(1, stateRegisteredTS)},
			horizon: stateHorizon,
			want:    ledger.RunActive,
		},
		{
			name: "withdrawn, and nothing since",
			chain: []event.Fields{
				registered(1, stateRegisteredTS),
				expired(2, stateLapseTS),
			},
			horizon: stateHorizon,
			want:    ledger.RunLapsed,
		},
		{
			name: "withdrawn, and the horizon has passed",
			chain: []event.Fields{
				registered(1, stateRegisteredTS),
				expired(2, stateLapseTS),
			},
			horizon: time.Hour,
			want:    ledger.RunAbandoned,
		},
		{
			// The run REC-017 is about: it lapsed, it came back, and the
			// credential it was released is newer than the withdrawal. A
			// directory that did not read `credential_issued` as activity
			// would call this run lapsed, and the reconciler reading the same
			// rule would then expect its entry to be gone.
			name: "restored: the credential it was released is newer than the lapse",
			chain: []event.Fields{
				registered(1, stateRegisteredTS),
				expired(2, stateLapseTS),
				credentialIssued(3, stateWorkedTS),
			},
			horizon: stateHorizon,
			want:    ledger.RunActive,
		},
		{
			name: "restored, worked, and lapsed again",
			chain: []event.Fields{
				registered(1, stateRegisteredTS),
				expired(2, stateLapseTS),
				credentialIssued(3, stateWorkedTS),
				expired(4, stateSecondLapse),
			},
			horizon: stateHorizon,
			want:    ledger.RunLapsed,
		},
		{
			name: "retired, and a straggling call after it",
			chain: []event.Fields{
				registered(1, stateRegisteredTS),
				retired(2, stateLapseTS),
				credentialIssued(3, stateWorkedTS),
			},
			horizon: stateHorizon,
			want:    ledger.RunRetired,
		},
		{
			name: "withdrawn, restored, worked, and then ended by its harness",
			chain: []event.Fields{
				registered(1, stateRegisteredTS),
				expired(2, stateLapseTS),
				credentialIssued(3, stateWorkedTS),
				retired(4, stateRetiredTS),
			},
			horizon: stateHorizon,
			want:    ledger.RunRetired,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, found, err := newDirectory(t, tc.chain).CredentialRun(context.Background(), testRunID)
			if err != nil {
				t.Fatalf("CredentialRun: %v", err)
			}
			if !found {
				t.Fatal("CredentialRun did not find a run the chain registers")
			}
			if got := run.State(now, tc.horizon); got != tc.want {
				t.Errorf("State(%s, %s) = %q, want %q\nfacts: retired_at=%s "+
					"withdrawn_at=%s last_activity_at=%s",
					stateNowTS, tc.horizon, got, tc.want,
					run.RetiredAt, run.ExpiredAt, run.LastActivityAt)
			}
		})
	}
}

// TestTheReaperIsNotTheRunSpeaking.
//
// `run_expired` carries the run's id and lands in the run's own events. If the
// directory counted it as activity, every withdrawal would be overtaken by
// itself the instant it was written and no run would ever read lapsed — the
// reaper reading its own record as evidence about the run it withdrew from.
// `source` is the discriminator, and this is what holds it there.
func TestTheReaperIsNotTheRunSpeaking(t *testing.T) {
	chain := []event.Fields{
		registered(1, stateRegisteredTS),
		expired(2, stateLapseTS),
	}
	run, _, err := newDirectory(t, chain).CredentialRun(context.Background(), testRunID)
	if err != nil {
		t.Fatalf("CredentialRun: %v", err)
	}
	if want := mustParse(t, stateRegisteredTS); !run.LastActivityAt.Equal(want) {
		t.Errorf("LastActivityAt is %s, want %s — the newest event the reaper did NOT "+
			"write is the registration, not the withdrawal that followed it",
			run.LastActivityAt, want)
	}
	if got := run.State(mustParse(t, stateNowTS), stateHorizon); got != ledger.RunLapsed {
		t.Errorf("a run whose only event after its registration is the reaper's own "+
			"withdrawal reads %q, want %q", got, ledger.RunLapsed)
	}
}

// mcpRunIsTheMCPsView keeps the compiler honest about which package's view is
// being asserted: State is mcp.CredentialRun's, and this file's subject is that
// the directory fills that view in well enough for it to be answerable.
var _ = func(r mcp.CredentialRun) string { return r.State(time.Now(), stateHorizon) }
