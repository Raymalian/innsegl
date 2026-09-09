// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
)

// LED-014 (proposed for doc 07; doc 07 is not modified here).
//
// A run retires ONCE. The ledger enforces it; the caller cannot.
//
// # The failure this exists for, measured rather than imagined
//
// MCP-011's fuzz campaign drew a kill 58ms into `retire_agent` and CI reported:
//
//	blind stratum 6, +58.394362ms: the chain holds 2 `run_retired` events for run
//
// It is seed-dependent — the same campaign passed under a different seed hours
// earlier — so it turns CI red at random rather than reliably, which is worse.
//
// # Why the caller cannot fix this
//
// ADR-0004 removed `idempotency_key` from `retire_agent` on the argument that
// "a run retires once" and a caller-supplied key would invent a way for two
// retirements of one run to disagree. Idempotency was to be intrinsic to
// `run_id`: the tool ASKS whether the run has been retired rather than deduping
// against a key.
//
// Asking is two steps. A SIGKILL does not cancel a transaction the process
// already sent, so the first attempt's INSERT can commit after the process is
// gone, and a replay that reads before that commit lands finds nothing and
// appends a second. `retire_agent.go`'s own header calls this window
// acceptable. IP §6.6 does not:
//
//	replaying any request after a crash returns the original result, never a
//	second identity, second event, or second commit.
//
// ADR-0004 chose a mechanism. It did not license dropping the guarantee.
//
// # Why the fix is a constraint and not more checking
//
// No amount of reading before writing closes a race between a read and a write.
// The check and the append have to be one act, and the only place that can be
// true is the database. A partial unique index needs no caller-supplied key, so
// it delivers ADR-0004's own sentence — "a run retires once" — as something the
// ledger enforces rather than something the caller intends.
func TestLED014ARunRetiresOnce(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	// NO idempotency_key, and the envelope already refuses one here — measured
	// while writing this test:
	//
	//   idempotency_key must be absent on run_retired; the MCP tool that emits
	//   it takes no idempotency key (ADR-0004)
	//
	// That is the whole difficulty in one line. Every other event type can fall
	// back on the store's dedupe; this one has nothing to dedupe against, so
	// two appends after a crash are two genuinely distinct requests and only
	// the run makes them one.
	retire := func() event.Fields {
		return event.Fields{
			event.FieldSchemaVersion: event.SchemaVersion,
			event.FieldEventType:     event.EventTypeRunRetired,
			event.FieldRunID:         "run-42",
			event.FieldSpiffeID:      "spiffe://innsegl.dev/agent/fix-ci/jira-118/run-42",
			event.FieldSource:        event.SourceMCP,
		}
	}

	if _, err := s.Append(ctx, retire()); err != nil {
		t.Fatalf("the first retirement must be accepted: %v", err)
	}

	_, err := s.Append(ctx, retire())
	if err == nil {
		t.Fatal("a second run_retired was accepted for the same run. IP §6.6: replaying " +
			"after a crash must never produce a second event, and I4 means the chain " +
			"would carry the duplicate forever")
	}
	if !strings.Contains(err.Error(), "run-42") {
		t.Errorf("the refusal was %q, which does not name the run whose retirement "+
			"already exists; a caller cannot act on that", err)
	}

	// The refusal must be a refusal, not a retry loop: Append retries when it
	// judges an error safe to retry, and a duplicate retirement never becomes
	// acceptable by trying again.
	if strings.Contains(err.Error(), "attempt") {
		t.Errorf("the refusal mentions attempts (%q), which suggests it was retried; "+
			"a constraint violation here is final", err)
	}
}

// TestLED015OtherEventsAreUnaffected. The constraint is scoped to one event
// type. A run appends many `tool_call` events and exactly one retirement, and
// an index that stopped the former would break every agent.
func TestLED015OtherEventsAreUnaffected(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := testCtx(t, 2*time.Minute)

	for n := range 5 {
		if _, err := s.Append(ctx, storeBody(n)); err != nil {
			t.Fatalf("tool_call %d for the same run was refused: %v — the constraint "+
				"must apply to run_retired and nothing else", n, err)
		}
	}
}
