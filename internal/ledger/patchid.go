// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/event"
)

// RunsForPatchID returns every run that recorded a given change (ADR-0047,
// RM-121, #193).
//
// # Why the key is the change and never the run
//
// This is the read behind verifying a rewritten commit: the verifier holds a
// commit whose signature a rebase destroyed, computes the change it makes, and
// asks who recorded it. Keying the lookup on the run the COMMIT CLAIMS would
// let the claim choose the evidence it is checked against — ask for run X's
// records, find one, conclude run X made this. Keyed on the change, the ledger
// answers who actually made it and the verifier compares.
//
// # Both `commit_intent` and `commit_recorded`
//
// The intent records the change before the signature exists and the recorded
// event after; a chain that crashed between them (IP §6.5's A → B window) holds
// only the first. A verifier that read only `commit_recorded` would report "the
// content changed" for a change that was signed and whose phase C the
// reconciler has not yet repaired, which is a wrong answer about a real
// signature.
//
// # The shape of the answer
//
// Every match, never one. A patch id identifies a change and not its maker, so
// the same change made twice by two agents has one id. Returning a single row
// would mean picking one of them and calling it the author.
func (s *Store) RunsForPatchID(ctx context.Context, patchID string) ([]ContentRecord, error) {
	return RunsForPatchID(ctx, s.pool, patchID)
}

// RunsForPatchID is the method's body over any pool.
//
// Exported over a pool for AssertReadableSchema's reason: the READ-ONLY query
// API (internal/api) is the surface that serves verdicts to strangers, and it
// holds a pool and no *Store. One query, one place it can be wrong.
func RunsForPatchID(ctx context.Context, pool *pgxpool.Pool, patchID string) ([]ContentRecord, error) {
	if patchID == "" {
		return nil, &StoreError{
			Class: ClassInvariantViolation, Op: "runs_for_patch_id", Retryable: false,
			Err: fmt.Errorf("an empty patch id names no change; every event that carries " +
				"none would match, which answers a question nobody asked"),
		}
	}

	rows, err := pool.Query(ctx,
		`SELECT canonical FROM innsegl.events
		  WHERE event_type = ANY($1)
		  ORDER BY chain_position`,
		[]string{event.EventTypeCommitIntent, event.EventTypeCommitRecorded})
	if err != nil {
		return nil, classify("runs_for_patch_id", err)
	}
	defer rows.Close()

	var out []ContentRecord
	seen := map[string]bool{}
	for rows.Next() {
		var canonical []byte
		if serr := rows.Scan(&canonical); serr != nil {
			return nil, classify("runs_for_patch_id", serr)
		}
		record, derr := decode(canonical)
		if derr != nil {
			return nil, derr
		}
		if got, isString := record[event.FieldPatchID].(string); !isString || got != patchID {
			continue
		}
		runID, isString := record[event.FieldRunID].(string)
		if !isString {
			continue
		}
		if runID == "" || seen[runID] {
			// One row per run. A run's intent and its recorded event name the
			// same change, and a verifier asking "did this run make this
			// change" is answered once.
			continue
		}
		seen[runID] = true

		// Both are strings by the time an event is in the chain -- the schema
		// is closed and validated at append -- so a wrong type here means the
		// stored bytes are not what they claim, and an empty string in the
		// answer is the honest report of that.
		eventID, _ := record[event.FieldEventID].(string) //nolint:errcheck // see above
		sha, _ := record[event.FieldCommitSHA].(string)   //nolint:errcheck // see above
		out = append(out, ContentRecord{
			RunID:     runID,
			PatchID:   patchID,
			CommitSHA: sha,
			EventID:   eventID,
		})
	}
	return out, rows.Err()
}

// ContentRecord is one run's record of one change.
//
// Declared here rather than imported from internal/verify, and the dependency
// runs the other way for a reason this package cares about: internal/verify
// holds no database and must keep holding none (VER-001 verifies with the
// ledger unreachable). It defines the interface it needs; this satisfies it.
type ContentRecord struct {
	RunID     string
	PatchID   string
	CommitSHA string
	EventID   string
}
